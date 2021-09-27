# Run the attack

Navigate to cbc-padding-oracle-adversary folder.

python3  -m venv  venv \
./venv/bin/activate \
pip install -r requirements.txt \
python3 ./cbc_padding_attack.py \
cat ./ quotes.tx