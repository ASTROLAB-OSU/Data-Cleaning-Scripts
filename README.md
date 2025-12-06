# Data Cleaning Steps
---
## Preparation
*Follow these instructions to create a custom filter for the dataset, skip to use our filter created from 4iQ data*
1. Make sure that the data to be cleaned is sorted into files by first letter, scripts are based on 4iQ data so the directory structure of that is known to work
2. create a new config for your dataset in ``data_cleaning/config/config.go`` populate this with the files you create in the following sections
2. navigate into preprocessing/cmd
3. run sort_by_pass.py to separately create a OrganizedPasswords directory
``
    python3 sort_by_pass.py
``
#### Follow on Distribution
1. navigate to the identify_suspicious_distribution directory
``
    cd preprocessing/cmd/identify_suspicious_distribution
``
2. run the script
	```go run main.go```
3. There will be entries put in "suspicious_distributions.csv" these need to be manually analyzed to see if the distribution anomalies are from artificial data or not.
4. move "preprocessing/results/suspicious_distributions.csv" into ``data_cleaning/config`` and update your config in ``data_cleaning/config/config.go``

#### Follow on Ratio
1. navigate to the generate_prefix_stats directory
``
    cd preprocessing/cmd/generate_prefix_stats
``
2. run the script
	```go run main.go```
3. navigate back to the cmd directory
	```cd ..```
4. run standalone_to_ratio_scatter.py
	```python3 standalone_to_ratio_scatter.py```
5. Looking at the output "for_graph.png", determine where you would like the line to go. Within the script you can adjust the cutoff line formula to see which passwords would be filtered.
6. Within ``preprocessing/follow_on_ratio/identify_passwords.go`` Update the calcCurve function to reflect the new cutoff line
7. navigate to the identify_suspicious_ratios directory
	```cd preprocessing/cmd/identify_suspicious_ratios```
8. run the script
	```go run main.go```
4. move "preprocessing/results/for_passwords.json" into ``data_cleaning/config`` and update your config in ``data_cleaning/config/config.go``

#### Email Chains
1. navigate to the cmd directory
	```cd preprocess/cmd```
2. run find_email_chains.py
	```python3 find_email_chains.py```
3. move "preprocessing/results/suspicious_email_groups/suspicious_chains.csv" into ``data_cleaning/config`` and update your config in ``data_cleaning/config/config.go``


## Cleaning
1. Change directory to data_cleaning 
	```cd data_cleaning```

*To count credentials that would be removed*
	```go run data_cleaning_script.go --dry-run --breach=[insert breach name here]```

*To remove artificial data*
	```go run data_cleaning_script.go --breach=[insert breach name here]```

The entries will be put into respective files in the data directory of you specified output file in config

### Extra Adjustments
For any adjustments to the filters such as prior work or rule-based, they are located in ``data_cleaning/cleaning``