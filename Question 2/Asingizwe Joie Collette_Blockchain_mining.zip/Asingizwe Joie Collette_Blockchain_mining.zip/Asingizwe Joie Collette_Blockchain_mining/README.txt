Blockchain Mining Simulation (Proof of Work)

1. Code Summary:
   - Defines a Block struct with index, timestamp, transactions, previousHash, hash, and nonce.
   - Uses SHA-256 from OpenSSL to compute block hashes.
   - Proof of Work requires finding a nonce that makes the block hash start with N zeros (difficulty).
   - Mining simulates adding new blocks with transactions.
   - Difficulty adjustment shows how mining time increases with higher difficulty.

2. Compilation:
   gcc blockchain_mining.c -o blockchain_mining -lcrypto

3. Run:
   ./blockchain_mining

4. Sample Output:
   Difficulty 3: ~0.04s
   Difficulty 4: ~1.32s

This shows that increasing difficulty makes mining slower and more secure.
