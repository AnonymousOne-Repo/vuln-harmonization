"""
field_completion_new_dbs.py - 专门为新增的三个数据库补全字段
只处理 Curl, Hunter, Ubuntu 三个数据库
"""

import pandas as pd
import json
import os
from typing import Dict, List, Optional
from pathlib import Path
import openai
import anthropic


class NewDatabaseFieldCompleter:
    """专门为新增数据库补全字段的引擎"""

    # 只处理这三个新数据库
    NEW_DATABASES = ['Curl', 'Hunter', 'Ubuntu']

    # 标准字段列表
    STANDARD_FIELDS = [
        'id', 'aliases', 'source', 'title', 'description',
        'published', 'modified', 'withdrawn', 'weaknesses',
        'severity', 'affected', 'references', 'primary_urls',
        'credits', 'acknowledgements', 'vendor_comments',
        'impacts', 'remediation', 'exploitation',
        'timeline', 'tags', 'related', 'vuln_status', 'cpe_configurations'
    ]

    # 可从文本中提取的字段
    EXTRACTABLE_FIELDS = {
        'weaknesses': ['title', 'description', 'tags'],
        'severity': ['description', 'title', 'impacts', 'exploitation'],
        'affected': ['title', 'description', 'remediation', 'vendor_comments'],
        'impacts': ['description', 'severity', 'weaknesses', 'remediation'],
        'credits': ['description', 'acknowledgements'],
        'remediation': ['description'],
        'exploitation': ['description'],
    }

    def __init__(self,
                 input_csv: str,
                 api_key: Optional[str] = None,
                 api_provider: str = 'openai'):
        """
        初始化

        Args:
            input_csv: 输入CSV文件（包含所有数据库的列）
            api_key: API key
            api_provider: 'openai' 或 'anthropic'
        """
        self.input_csv = input_csv
        self.df = None
        self.api_provider = api_provider

        # 初始化API客户端
        api_key = "sk-"

        # 初始化API
        if api_provider == 'openai':
            self.api_key = api_key or "YOUR_OPENAI_KEY"
            self.client = openai.OpenAI(api_key=self.api_key)
            self.model = "gpt-4o-mini"
        elif api_provider == 'anthropic':
            self.api_key = api_key or "YOUR_ANTHROPIC_KEY"
            self.client = anthropic.Anthropic(api_key=self.api_key)
            self.model = "claude-sonnet-4-20250514"

    def load_data(self):
        """加载CSV数据"""
        print("=" * 80)
        print("Loading Data for New Database Completion")
        print("=" * 80)

        print(f"\n📖 Reading: {self.input_csv}")
        self.df = pd.read_csv(self.input_csv)

        # 检查新数据库列是否存在
        missing_cols = [db for db in self.NEW_DATABASES if db not in self.df.columns]
        if missing_cols:
            raise ValueError(f"Missing columns in CSV: {missing_cols}")

        print(f"   ✓ Loaded {len(self.df):,} CVEs")
        print(f"   ✓ Target databases: {', '.join(self.NEW_DATABASES)}")

    def _is_field_empty(self, value, field_name: str = None) -> bool:
        """判断字段是否为空"""
        if value is None:
            return True

        if isinstance(value, str):
            if not value.strip():
                return True

        if isinstance(value, list):
            if len(value) == 0:
                return True
            # 检查是否全是空值
            if all(self._is_field_empty(item) for item in value):
                return True

        if isinstance(value, dict):
            if len(value) == 0:
                return True
            # 对于特定字段的特殊处理
            if field_name == 'exploitation':
                exploits = value.get('exploits', [])
                epss = value.get('epss', [])
                return len(exploits) == 0 and len(epss) == 0
            if field_name == 'remediation':
                solutions = value.get('solutions', [])
                workarounds = value.get('workarounds', [])
                return len(solutions) == 0 and len(workarounds) == 0

        return False

    def identify_missing_fields_for_new_dbs(self, cve_id: str) -> Dict[str, Dict]:
        """
        识别新数据库中需要补全的字段

        策略：
        1. 读取该CVE在新数据库中的数据
        2. 检查哪些字段为空
        3. 查看其他数据库是否有该字段的值
        4. 确定可以从本数据库的哪些字段提取

        Returns:
            {
                'Curl': {'missing_fields': [...], 'source_data': {...}, ...},
                'Hunter': {...},
                'Ubuntu': {...}
            }
        """
        row = self.df[self.df['CVE_ID'] == cve_id]

        if row.empty:
            return {}

        # 解析所有数据库的数据（包括新旧数据库）
        all_db_data = {}
        all_databases = [col for col in self.df.columns if col != 'CVE_ID']

        for db_name in all_databases:
            json_str = row[db_name].iloc[0]
            try:
                data = json.loads(json_str)
                if 'error' not in data:
                    all_db_data[db_name] = data
            except:
                continue

        if not all_db_data:
            return {}

        # 找出所有数据库中有值的字段
        fields_with_values = set()
        field_to_source_dbs = {}

        for field in self.STANDARD_FIELDS:
            dbs_with_this_field = []

            for db_name, data in all_db_data.items():
                field_value = data.get(field)
                if not self._is_field_empty(field_value, field):
                    dbs_with_this_field.append(db_name)

            if dbs_with_this_field:
                fields_with_values.add(field)
                field_to_source_dbs[field] = dbs_with_this_field

        print(f"\n📊 CVE {cve_id} - Fields analysis:")
        print(f"   Fields with values across all DBs: {len(fields_with_values)}")

        # 只对新数据库进行补全分析
        completion_tasks = {}

        for db_name in self.NEW_DATABASES:
            # 检查该数据库是否有数据
            if db_name not in all_db_data:
                print(f"   ⚠️  {db_name}: No data available")
                continue

            data = all_db_data[db_name]
            missing_fields = []
            available_sources = {}
            reference_dbs = {}

            for field in fields_with_values:
                field_value = data.get(field)

                # 该字段在本数据库为空
                if self._is_field_empty(field_value, field):
                    # 检查是否可从本数据库的其他字段提取
                    if field in self.EXTRACTABLE_FIELDS:
                        source_fields = self.EXTRACTABLE_FIELDS[field]

                        valid_sources = []
                        for src_field in source_fields:
                            src_value = data.get(src_field)
                            if not self._is_field_empty(src_value, src_field):
                                valid_sources.append(src_field)

                        if valid_sources:
                            missing_fields.append(field)
                            available_sources[field] = valid_sources
                            reference_dbs[field] = field_to_source_dbs.get(field, [])

            if missing_fields:
                # 总是添加exploitation字段
                if 'exploitation' not in missing_fields:
                    if not self._is_field_empty(data.get('description'), 'description'):
                        missing_fields.append('exploitation')
                        available_sources['exploitation'] = ['description']
                        reference_dbs['exploitation'] = field_to_source_dbs.get('exploitation', [])

                completion_tasks[db_name] = {
                    'missing_fields': missing_fields,
                    'source_data': data,
                    'available_sources': available_sources,
                    'reference_dbs': reference_dbs
                }

                print(f"   📋 {db_name}: {len(missing_fields)} missing fields")

        return completion_tasks

    def generate_completion_prompt(self, cve_id: str, db_name: str, task_info: Dict) -> str:
        """生成补全提示词"""
        missing_fields = task_info['missing_fields']
        source_data = task_info['source_data']
        available_sources = task_info['available_sources']

        # 收集所有需要的源字段
        all_source_fields = set()
        for field in missing_fields:
            all_source_fields.update(available_sources[field])

        prompt = f"""You are a vulnerability data extraction assistant. Extract missing fields from source data.

**CVE ID:** {cve_id}
**Source Database:** {db_name}
**Task:** Complete {len(missing_fields)} missing fields

## Available Source Data

"""

        # 添加源数据
        for src_field in sorted(all_source_fields):
            src_value = source_data.get(src_field)
            if src_value is None:
                continue

            # 截断过长内容
            if isinstance(src_value, str):
                if len(src_value) > 3000:
                    src_value = src_value[:3000] + '\n... (truncated)'
            elif isinstance(src_value, list):
                if len(src_value) > 15:
                    src_value = src_value[:15] + ['... (truncated)']

            prompt += f"### {src_field}\n\n"

            if isinstance(src_value, (dict, list)):
                prompt += f"```json\n{json.dumps(src_value, indent=2, ensure_ascii=False)}\n```\n\n"
            else:
                prompt += f"{src_value}\n\n"

        # 添加字段定义
        prompt += f"## Fields to Extract ({len(missing_fields)} fields)\n\n"

        for idx, field in enumerate(missing_fields, 1):
            prompt += f"### {idx}. {field}\n"
            prompt += f"Extract this field from the source data above.\n\n"

        # 添加提取规则
        prompt += """## CRITICAL EXTRACTION RULES

**YOU MUST FOLLOW THESE RULES:**

1. **EXTRACT ONLY** - No inference, no external knowledge
2. **EXACT WORDING** - Use the exact terminology from source data
3. **NO ASSUMPTIONS** - If information is not explicitly present, return null or []
4. **STRICT NULL HANDLING** - When in doubt, return null rather than guess

## Output Format

Return valid JSON with ONLY the extracted fields:

```json
{
"""

        for idx, field in enumerate(missing_fields):
            if 'array' in str(type([])):
                prompt += f'  "{field}": []'
            else:
                prompt += f'  "{field}": null'

            if idx < len(missing_fields) - 1:
                prompt += ','
            prompt += '\n'

        prompt += """}
```

Return ONLY valid JSON, no explanations.
"""

        return prompt

    def call_llm_for_completion(self, prompt: str, max_tokens: int = 4096) -> Optional[Dict]:
        """调用LLM API"""
        if not self.api_key:
            print("❌ No API key")
            return None

        try:
            if self.api_provider == 'openai':
                return self._call_openai(prompt, max_tokens)
            elif self.api_provider == 'anthropic':
                return self._call_anthropic(prompt, max_tokens)
        except Exception as e:
            print(f"   ⚠️  API error: {e}")
            return None

    def _call_openai(self, prompt: str, max_tokens: int) -> Optional[Dict]:
        """调用OpenAI API"""
        system_prompt = """You are a precise data extraction assistant. 
Extract ONLY explicit information from provided source data.
Use EXACT wording. Return null when information is not present.
NEVER infer or use external knowledge."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0,
                response_format={"type": "json_object"}
            )

            response_text = response.choices[0].message.content.strip()
            return json.loads(response_text)

        except Exception as e:
            print(f"   ⚠️  OpenAI error: {e}")
            return None

    def _call_anthropic(self, prompt: str, max_tokens: int) -> Optional[Dict]:
        """调用Anthropic API"""
        system_prompt = """You are a precise data extraction assistant.
Extract ONLY explicit information from provided source data.
Use EXACT wording. Return null when information is not present.
NEVER infer or use external knowledge."""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()

            # 清理markdown代码块
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            elif response_text.startswith('```'):
                response_text = response_text[3:]

            if response_text.endswith('```'):
                response_text = response_text[:-3]

            return json.loads(response_text.strip())

        except Exception as e:
            print(f"   ⚠️  Anthropic error: {e}")
            return None

    def merge_completed_fields(self, original_data: Dict, completed_fields: Dict) -> Dict:
        """合并补全的字段到原始数据"""
        merged_data = original_data.copy()

        for field, value in completed_fields.items():
            if field in merged_data:
                if self._is_field_empty(merged_data[field], field):
                    merged_data[field] = value
            else:
                merged_data[field] = value

        return merged_data

    def complete_single_cve(self, cve_id: str) -> Dict[str, Dict]:
        """补全单个CVE的新数据库字段"""
        tasks = self.identify_missing_fields_for_new_dbs(cve_id)

        if not tasks:
            return {}

        print(f"  📊 Found {len(tasks)} database(s) to process")

        completed_results = {}

        for db_name, task_info in tasks.items():
            missing_fields = task_info['missing_fields']

            print(f"    - {db_name}: {len(missing_fields)} fields ({', '.join(missing_fields)})")

            if not missing_fields:
                completed_results[db_name] = task_info['source_data']
                continue

            # 生成prompt
            prompt = self.generate_completion_prompt(cve_id, db_name, task_info)

            # 调用LLM
            completed_fields = self.call_llm_for_completion(prompt)

            if completed_fields:
                valid_fields = {k: v for k, v in completed_fields.items() if k in missing_fields}

                if len(valid_fields) < len(completed_fields):
                    print(f"      ⚠️  Filtered {len(completed_fields) - len(valid_fields)} unexpected fields")

                merged_data = self.merge_completed_fields(
                    task_info['source_data'],
                    valid_fields
                )

                completed_results[db_name] = merged_data
                print(f"      ✅ Completed {len(valid_fields)} fields")
            else:
                print(f"      ❌ Failed")

        return completed_results

    def batch_complete_new_databases(self,
                                     output_csv: str = None,
                                     max_cves: int = None):
        """
        批量补全新数据库的字段（增量更新）

        工作流程：
        1. 检查output_csv是否存在
        2. 如果存在，读取已处理的CVE列表
        3. 只处理未处理的CVE
        4. 逐行处理并追加到CSV

        Args:
            output_csv: 输出CSV文件（默认在原文件上更新）
            max_cves: 最大处理数量
        """
        if output_csv is None:
            output_csv = self.input_csv.replace('.csv', '_completed_new_dbs.csv')

        print("\n" + "=" * 80)
        print("Batch Completion for New Databases (Curl, Hunter, Ubuntu)")
        print("=" * 80)

        # Step 1: 检查已处理的CVE
        processed_cves = set()
        file_exists = Path(output_csv).exists()

        if file_exists:
            print(f"\n📂 Found existing output: {output_csv}")
            try:
                df_existing = pd.read_csv(output_csv)
                processed_cves = set(df_existing['CVE_ID'].tolist())
                print(f"   ✓ Already processed: {len(processed_cves):,} CVEs")
            except Exception as e:
                print(f"   ⚠️  Warning: {e}")
                file_exists = False
        else:
            print(f"\n📄 Creating new file: {output_csv}")

        # Step 2: 确定要处理的CVE
        all_cves = self.df['CVE_ID'].tolist()
        cves_to_process = [cve for cve in all_cves if cve not in processed_cves]

        if max_cves:
            cves_to_process = cves_to_process[:max_cves]

        print(f"\n📊 Processing plan:")
        print(f"   Total CVEs: {len(self.df):,}")
        print(f"   Already processed: {len(processed_cves):,}")
        print(f"   To process: {len(cves_to_process):,}")

        if not cves_to_process:
            print(f"\n✅ All CVEs already processed!")
            return

        # Step 3: 准备CSV文件
        if not file_exists:
            with open(output_csv, 'w', encoding='utf-8', newline='') as f:
                import csv
                columns = list(self.df.columns)
                writer = csv.DictWriter(f, fieldnames=columns)
                writer.writeheader()

        # Step 4: 逐行处理
        total_completed = 0
        total_skipped = 0
        total_failed = 0

        print(f"\n🔄 Processing CVEs...")
        print("=" * 80 + "\n")

        for idx, cve_id in enumerate(cves_to_process, 1):
            print(f"[{idx}/{len(cves_to_process)}] {cve_id}")

            try:
                # 获取原始行
                original_row = self.df[self.df['CVE_ID'] == cve_id]

                if original_row.empty:
                    print(f"  ❌ Not found in input")
                    total_failed += 1
                    continue

                # 创建输出行
                output_row = original_row.iloc[0].to_dict()

                # 补全新数据库字段
                completed_results = self.complete_single_cve(cve_id)

                if completed_results:
                    # 更新新数据库的列
                    for db_name, completed_data in completed_results.items():
                        output_row[db_name] = json.dumps(completed_data, ensure_ascii=False)

                    total_completed += 1
                    print(f"  ✅ Updated {len(completed_results)} databases")
                else:
                    total_skipped += 1
                    print(f"  ✓ No updates needed")

                # 追加到CSV
                with open(output_csv, 'a', encoding='utf-8', newline='') as f:
                    import csv
                    columns = list(self.df.columns)
                    writer = csv.DictWriter(f, fieldnames=columns)
                    writer.writerow(output_row)

                # 定期显示进度
                if idx % 10 == 0:
                    print(f"\n  💾 Progress: {idx}/{len(cves_to_process)}\n")

            except KeyboardInterrupt:
                print(f"\n\n⚠️  Interrupted!")
                print(f"   Processed: {total_completed + total_skipped}/{len(cves_to_process)}")
                print(f"   Progress saved to: {output_csv}")
                raise

            except Exception as e:
                print(f"  ❌ Error: {e}")
                total_failed += 1

                # 保存原始数据
                try:
                    with open(output_csv, 'a', encoding='utf-8', newline='') as f:
                        import csv
                        columns = list(self.df.columns)
                        writer = csv.DictWriter(f, fieldnames=columns)
                        writer.writerow(output_row)
                except:
                    pass

        # 统计
        print(f"\n" + "=" * 80)
        print("Completion Summary")
        print("=" * 80)
        print(f"CVEs processed: {len(cves_to_process):,}")
        print(f"  - Completed with updates: {total_completed:,}")
        print(f"  - No updates needed: {total_skipped:,}")
        print(f"  - Failed: {total_failed:,}")
        print(f"\n✅ Results saved to: {output_csv}")
        print(f"   Total CVEs: {len(processed_cves) + len(cves_to_process):,}")


def main():
    """主函数"""
    import sys

    if len(sys.argv) < 2:
        print("=" * 80)
        print("New Database Field Completion (Curl, Hunter, Ubuntu)")
        print("=" * 80)
        print("\nUsage:")
        print("  python field_completion_new_dbs.py <CSV_FILE> [options]")
        print("\nOptions:")
        print("  --output FILE       Output CSV file (default: input_completed_new_dbs.csv)")
        print("  --max N            Process maximum N CVEs")
        print("  --provider NAME    API provider: openai (default) or anthropic")
        print("\nExamples:")
        print("  python field_completion_new_dbs.py cve_results.csv")
        print("  python field_completion_new_dbs.py cve_results.csv --max 100")
        print("  python field_completion_new_dbs.py cve_results.csv --output cve_results_completed.csv")
        return

    csv_file = sys.argv[1]

    if not Path(csv_file).exists():
        print(f"❌ File not found: {csv_file}")
        return

    # 解析参数
    output_csv = None
    max_cves = None
    api_provider = 'openai'

    for i in range(2, len(sys.argv)):
        if sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output_csv = sys.argv[i + 1]
        elif sys.argv[i] == '--max' and i + 1 < len(sys.argv):
            max_cves = int(sys.argv[i + 1])
        elif sys.argv[i] == '--provider' and i + 1 < len(sys.argv):
            api_provider = sys.argv[i + 1]

    # 初始化引擎
    engine = NewDatabaseFieldCompleter(csv_file, api_provider=api_provider)
    engine.load_data()

    # 批量补全
    engine.batch_complete_new_databases(
        output_csv=output_csv,
        max_cves=max_cves
    )


if __name__ == '__main__':
    main()

    #  python field_completion_more.py output/cve_results.csv