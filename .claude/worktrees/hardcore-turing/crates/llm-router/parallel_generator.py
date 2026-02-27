#!/usr/bin/env python3
"""
Multi-Agent Parallel Training Data Generator
Her ajan bir dataset grubunu işler, sonuçlar birleştirilir.
"""

from datasets import load_dataset
import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from multiprocessing import Manager, cpu_count
import re
import time
from datetime import datetime

# =============================================================================
# AGENT ASSIGNMENTS (Her ajan bir grup dataset işler)
# =============================================================================

AGENT_TASKS = {
    "AGENT_ALPHA": [
        # Büyük instruction datasets
        ("Open-Orca/OpenOrca", None, "question", 500000),
        ("stingning/ultrachat", None, "data", 300000),
        ("HuggingFaceH4/ultrachat_200k", None, "messages", 200000),
    ],
    "AGENT_BRAVO": [
        # WizardLM & Hermes
        ("teknium/openhermes", None, "instruction", 240000),
        ("WizardLM/WizardLM_evol_instruct_V2_196k", None, "instruction", 196000),
        ("WizardLM/WizardLM_evol_instruct_70k", None, "instruction", 70000),
    ],
    "AGENT_CHARLIE": [
        # OpenAssistant & Community
        ("OpenAssistant/oasst1", None, "text", 160000),
        ("OpenAssistant/oasst2", None, "text", 130000),
        ("databricks/dolly-15k", None, "instruction", 15000),
        ("yahma/alpaca-cleaned", None, "instruction", 52000),
        ("tatsu-lab/alpaca", None, "instruction", 52000),
    ],
    "AGENT_DELTA": [
        # Code datasets
        ("m-a-p/CodeFeedback-Filtered-Instruction", None, "query", 160000),
        ("nickrosh/Evol-Instruct-Code-80k", None, "instruction", 80000),
        ("sahil2801/CodeAlpaca-20k", None, "instruction", 20000),
        ("TokenBender/code_instructions_122k", None, "instruction", 122000),
        ("theblackcat102/evol-codealpaca-v1", None, "instruction", 110000),
    ],
    "AGENT_ECHO": [
        # Math datasets
        ("microsoft/orca-math-word-problems-200k", None, "question", 200000),
        ("meta-math/MetaMathQA", None, "query", 400000),
        ("TIGER-Lab/MathInstruct", None, "instruction", 260000),
        ("gsm8k", "main", "question", 8500),
    ],
    "AGENT_FOXTROT": [
        # QA datasets
        ("squad_v2", None, "question", 150000),
        ("hotpot_qa", "fullwiki", "question", 113000),
        ("trivia_qa", "rc", "question", 95000),
        ("natural_questions", "default", "question", 100000),
    ],
    "AGENT_GOLF": [
        # More QA & Knowledge
        ("eli5_category", None, "title", 100000),
        ("yahoo_answers_qa", None, "question", 87000),
        ("quac", None, "question", 83000),
        ("sciq", None, "question", 14000),
    ],
    "AGENT_HOTEL": [
        # Reasoning & Logic
        ("allenai/ai2_arc", "ARC-Challenge", "question", 2500),
        ("allenai/ai2_arc", "ARC-Easy", "question", 5200),
        ("Rowan/hellaswag", None, "ctx", 50000),
        ("allenai/winogrande", "winogrande_xl", "sentence", 44000),
        ("piqa", None, "goal", 16000),
        ("boolq", None, "question", 16000),
    ],
    "AGENT_INDIA": [
        # Summarization
        ("cnn_dailymail", "3.0.0", "article", 100000),
        ("xsum", None, "document", 100000),
        ("samsum", None, "dialogue", 16000),
        ("multi_news", None, "document", 56000),
    ],
    "AGENT_JULIET": [
        # Conversation & Dialog
        ("blended_skill_talk", None, "free_messages", 76000),
        ("empathetic_dialogues", None, "utterance", 25000),
        ("daily_dialog", None, "dialog", 13000),
        ("Anthropic/hh-rlhf", None, "chosen", 100000),
    ],
    "AGENT_KILO": [
        # Science & Technical
        ("camel-ai/physics", None, "message_1", 20000),
        ("camel-ai/chemistry", None, "message_1", 20000),
        ("camel-ai/biology", None, "message_1", 20000),
        ("camel-ai/math", None, "message_1", 50000),
    ],
    "AGENT_LIMA": [
        # Multilingual & Turkish
        ("malhajar/alpaca-gpt4-tr", None, "instruction", 52000),
        ("garage-bAInd/Open-Platypus", None, "instruction", 25000),
        ("GAIR/lima", None, "conversations", 1000),
        ("teknium/GPT4-LLM-Cleaned", None, "instruction", 50000),
    ],
}

# =============================================================================
# COMPLEXITY PATTERNS
# =============================================================================

ECONOMY_PATTERNS = [
    r'^(hi|hello|hey|merhaba|selam|thanks|thank you|bye|yes|no|ok)\b',
    r'^what is \w+\?$',
    r'^who is \w+\?$',
    r'^define \w+$',
    r'^\d+\s*[\+\-\*\/]\s*\d+',
    r'ne demek\?$',
    r'nedir\?$',
]

PREMIUM_PATTERNS = [
    r'design (a |an )?(system|architecture|database|api)',
    r'(analyze|evaluate|assess).{20,}',
    r'(comprehensive|detailed|in.depth)',
    r'(trade.?off|pros and cons)',
    r'(prove|proof|theorem)',
    r'(optimize|refactor).{30,}',
    r'step.by.step.{30,}',
]

STANDARD_PATTERNS = [
    r'^write (a |an )?(function|code|script)',
    r'^explain\b',
    r'^how (do|does|to|can)',
    r'summarize',
    r'translate',
    r'^list\b',
    r'^compare\b',
]

def classify(text):
    if not text or len(text) < 10:
        return None

    text_lower = text.lower().strip()
    tokens = len(text.split())

    if tokens <= 5:
        return "economy"

    for p in PREMIUM_PATTERNS:
        if re.search(p, text_lower):
            return "premium"

    for p in ECONOMY_PATTERNS:
        if re.search(p, text_lower):
            return "economy"

    for p in STANDARD_PATTERNS:
        if re.search(p, text_lower):
            return "standard"

    if tokens > 80:
        return "premium"
    elif tokens > 25:
        return "standard"
    return "economy"

def extract_text(item, field):
    if field and field in item:
        val = item[field]
        if isinstance(val, str):
            return val
        if isinstance(val, list) and val:
            if isinstance(val[0], str):
                return val[0]
            if isinstance(val[0], dict):
                return val[0].get("content", val[0].get("value", ""))

    for f in ["instruction", "question", "query", "text", "input", "prompt"]:
        if f in item and isinstance(item[f], str):
            return item[f]

    if "conversations" in item and item["conversations"]:
        conv = item["conversations"][0]
        if isinstance(conv, dict):
            return conv.get("value", conv.get("content", ""))

    if "messages" in item and item["messages"]:
        msg = item["messages"][0]
        if isinstance(msg, dict):
            return msg.get("content", "")

    return None

# =============================================================================
# AGENT WORKER
# =============================================================================

def agent_worker(agent_name, datasets, shared_seen):
    """Tek bir ajan - kendi dataset grubunu işler"""

    result = {"economy": [], "standard": [], "premium": []}
    local_count = 0

    print(f"🤖 {agent_name} started - {len(datasets)} datasets")

    for name, config, field, max_ex in datasets:
        try:
            ds = load_dataset(name, config, split="train", streaming=True)
            count = 0

            for item in ds:
                if count >= max_ex:
                    break

                text = extract_text(item, field)
                if not text or len(text) < 10:
                    continue

                text = text.strip()
                text_hash = hash(text[:100])

                # Thread-safe duplicate check
                if text_hash in shared_seen:
                    continue
                shared_seen[text_hash] = True

                cat = classify(text)
                if cat:
                    result[cat].append(text)
                    count += 1
                    local_count += 1

            print(f"   {agent_name}: ✅ {name.split('/')[-1]} ({count:,})")

        except Exception as e:
            print(f"   {agent_name}: ❌ {name} - {str(e)[:50]}")

    print(f"🏁 {agent_name} finished - {local_count:,} total examples")
    return agent_name, result

# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

def main():
    start_time = time.time()

    print("=" * 70)
    print("🚀 MULTI-AGENT PARALLEL TRAINING DATA GENERATOR")
    print("=" * 70)
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🤖 Agents: {len(AGENT_TASKS)}")
    print(f"💻 CPU cores: {cpu_count()}")
    print("=" * 70)

    # Shared deduplication set (thread-safe)
    manager = Manager()
    shared_seen = manager.dict()

    # Final results
    final_result = {"economy": [], "standard": [], "premium": []}

    # Run agents in parallel
    max_workers = min(len(AGENT_TASKS), cpu_count())
    print(f"\n🔄 Running {max_workers} agents in parallel...\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(agent_worker, agent_name, datasets, shared_seen): agent_name
            for agent_name, datasets in AGENT_TASKS.items()
        }

        for future in as_completed(futures):
            agent_name = futures[future]
            try:
                _, result = future.result()

                # Merge results
                for cat in ["economy", "standard", "premium"]:
                    final_result[cat].extend(result[cat])

                print(f"✅ {agent_name} merged: E={len(result['economy']):,}, S={len(result['standard']):,}, P={len(result['premium']):,}")

            except Exception as e:
                print(f"❌ {agent_name} failed: {e}")

    # Final stats
    elapsed = time.time() - start_time
    total = sum(len(v) for v in final_result.values())

    print("\n" + "=" * 70)
    print("📊 FINAL RESULTS")
    print("=" * 70)
    print(f"Economy:  {len(final_result['economy']):,} examples")
    print(f"Standard: {len(final_result['standard']):,} examples")
    print(f"Premium:  {len(final_result['premium']):,} examples")
    print(f"{'─' * 40}")
    print(f"TOTAL:    {total:,} examples")
    print(f"⏱️  Time:   {elapsed/60:.1f} minutes")
    print(f"⚡ Speed:  {total/elapsed:.0f} examples/second")
    print("=" * 70)

    # Save
    output_path = "training_data.json"
    print(f"\n💾 Saving to {output_path}...")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_result, f, ensure_ascii=False, indent=2)

    import os
    size_mb = os.path.getsize(output_path) / (1024 * 1024)

    print(f"✅ Saved: {output_path}")
    print(f"📁 Size: {size_mb:.1f} MB")
    print(f"\n🎉 COMPLETE!")

if __name__ == "__main__":
    main()
