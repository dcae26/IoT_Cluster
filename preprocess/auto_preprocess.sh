echo "Preprocessing the raw instance..."
echo "Building data analysis tool..."

# Preprocess Step 1: build spatial features
# goto data analysis tool directory
cd ./data_analysis

# build thee analysis tool
make

# usage: <program> <config path> <data path> <output path>
# data path should contain:
#  - [raw_data.csv], bag_ports.csv, bag_domain.csv, bag_cipher_suite.csv
#  - nw_feature.csv, stage1_vec.csv and info.csv
# output depends on the mode of the tool
# advanced configureation see https://github.com/EvanBin/IoT_Classter
./bin/dataAnalysis ./bin ../../result ../../result

# clean or remove the build
make remove

# Preprocess Step 2: build temporal features
echo ""
echo "First step of encoded Instance done."
echo "Building temporal features..."

# goto temporal calculation tool directory
cd ..

# need to have python 3, if use python 2 change command to "python"
# require Numpy and Pandas
# if the data path is changed, modify step3_VAE_preprocess.py
python3 ./VAE_preprocess.py

echo "Preprocessing done."
