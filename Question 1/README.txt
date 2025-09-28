UTXO Simulation - README

Files:
 - utxo_simulation.c   (C source)
 - README_utxo.txt     (this file)

How the code works:
 - The program keeps an in-memory array of UTXOs (id, address, amount, spent flag).
 - Transactions take one or more UTXOs as inputs, mark them spent, create a UTXO for the receiver and a change UTXO for the sender (if change>0).
 - The program contains a demo mode (run with: ./utxo_simulation demo) that initializes sample UTXOs and executes two transactions automatically.
 - Interactive mode (./utxo_simulation) lets you view UTXOs and perform transactions with manual or automatic input selection.

Sample commands:
 - Compile: gcc utxo_simulation.c -o utxo_simulation
 - Demo run: ./utxo_simulation demo
 - Interactive: ./utxo_simulation

Sample I/O (demo):
 - You will see initial UTXOs for Alice/Bob/Carol, then transactions:
   Alice -> Bob 60  (uses 50+30 -> change 20 back to Alice)
   Bob -> Carol 50  (uses Bob's UTXOs)
 - After each tx the program prints the updated UTXO set.

Notes:
 - Amounts are integers for simplicity.
 - Replace YourFullName in the ZIP filename: YourFullName_UTXO_Blockchain.zip


