rm -f ~/.viminfo

python3 action_gen.py --prepare-vim-workspace
python3 action_gen.py -o action.act -n 500
python3 hotspot_finder.py -c "vim" --wd ./vimworkspace -a action.act -t pin -k 1 -l 200 -o hotspots.txt
python3 syscall_tracer.py -c "vim" --wd ./vimworkspace -a action.act -i hotspots.txt -o pintool_trace.json
python3 ground_truth_generator.py -k 2 --kl 4 -i pintool_trace.json -o output/test/ground_truth
