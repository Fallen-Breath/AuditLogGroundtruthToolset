rm -f ~/.viminfo
python3 ground_truth_generator.py -c "vim" -k 2 --kl 4 -i hotspots.txt -o output/ground_truth -a actions/edit.act --wd ./vimworkspace
