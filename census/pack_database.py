'''
This script packs the Census PUMS data in this folder into a set of binary database entries
that can be loaded by the prover for queries.

Data -> Compressed size:

    AGEP (age)       --> 7 bits
    SEX (sex)        --> 1 bit
    PINCP (income)   --> 23 bits
    SCHL (education) --> 6 bits

    total entry size: 37 bits (padded up to 64)
        lsb                                  msb
          AAAAAAASIIIIIIIIIIIIIIIIIIIIIIISSSSSS
          0123456789012345678901234567890123456

Outputs > census_db.bin
'''

import pandas as pd
import struct

# Load the data
data = pd.read_csv('census_pums_2018.csv')

entry_bytes = bytearray()

for i, row in data.iterrows():

    age, sex, income, education = int(row['AGEP']), int(row['SEX']), int(row['PINCP']), int(row['SCHL'])
    
    result = age & 0x7f
    result |= sex & 0x1 << 7
    result |= (income & 0x7fffff) << 8
    result |= education & 0x3f << 31

    if i < 10:
        print(f'result: {result:x}, income: {income:x}, retrieved_shifted: {(result >> 8) & 0x7fffff:x}')

    entry_bytes.extend(struct.pack('q', result))

with open('census_db.bin', 'wb') as f:
    f.write(entry_bytes)


