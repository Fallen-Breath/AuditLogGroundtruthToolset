rm -f ~/.viminfo

python3 action_gen.py
python3 ground_truth_generator.py -c "vim" -k 2 --kl 4 -i hotspots.txt -o output/auto/ground_truth -a action.act --wd ./vimworkspace
