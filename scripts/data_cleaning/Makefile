.PHONY: count clean

# count the entries without removing any
count:
	echo "Building and running data counting script..."
	go run data_counting_script.go data_cleaning_emails.go data_cleaning_fod.go data_cleaning_for.go

# remove artifical entries as they are found
clean:
	echo "Building and running data cleaning script..."
	go run data_cleaning_script.go data_cleaning_emails.go data_cleaning_fod.go data_cleaning_for.go
