rm -f ~/.viminfo
# python3 ground_truth_generator.py -c "vim" -k 2 --kl 4 -i hotspots.txt -o output/edit/ground_truth -a actions/edit.act --wd ./vimworkspace
python3 ground_truth_generator.py -c "vim" -k 2 --kl 4 -i hotspots.txt -o output/file/ground_truth -a actions/file.act --wd ./vimworkspace
