# Data Cleaning Steps
---
## Preparation
1. Make sure that the data to be cleaned is in the data directory and is sorted into files by first letter, scripts are based on 4iQ data so the directory structure of that is known to work
2. go into the scripts directory
``
cd scripts
``
3. run sort_by_pass.py to separately create a OrganizedPasswords directory
``
    python3 sort_by_pass.py
``
#### Follow on Distribution
*Follow these instructions to create a custom filter for the dataset, skip to use our filter created from 4iQ data*
1. run calc_distribution.go
	```go run calc_distribution.go trie.go```
2. run distribution_convert_to_json.py
	```python3 distribution_convert_to_json.py```
3. run prefix extractor.go
	```go run prefix_extractor.go trie.go```
4. There will be entries put in "suspicious_distributions.txt" these need to be manually analyzed to see if the distribution anomalies are from artificial data or not.
5. update removePasswordsSpecific and removePasswordsAll within data_cleaning/data_cleaning_fod.go

#### Follow on Ratio
1. run standalone_to_ratio_stats.go
	```go run standalone_to_ratio_stats.go trie.go```

	*Do the following steps for a custom follow on ratio cutoff*
	1. run standalone_to_ratio_scatter.py
			```python3 standalone_to_ratio_scatter.py```
	2. Looking at the output "for_graph.png", determine where you would like the line to go
	3. Update the calcCurve function in for_identify_passwords.go to reflect the new cutoff line

2. run for_identify_passwords.go
	```go run for_identify_passwords.go```


## Cleaning
1. Change directory to data_cleaning ```cd data_cleaning```

*To count credentials that would be removed*
	```make count```

*To remove artificial data*
	```make clean```

The entries will be put into respective files in the data directory

### Extra Adjustments
For any adjustments to the prior works filters, they are located in data_cleaning_script.go within the function priorWorkChecks.

New rule based filters are within data_cleaning_script.go in removeRuleBased.

FBOBH filters are located in the removeFBOB function in data_cleaning_script.go.

All other filters are within their own file in the data_cleaning directory.