python3 hotspot_finder.py -c vim -t pin -k 1 -o hotspots.txt
python3 ground_truth_generator.py -c vim -k 2 -i hotspots.txt -o ground_truth.json
