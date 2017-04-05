## Insight Data Engineering Code Challenge

Code challenge submission for the Insight NASA fansite analytics project. 

To execute the project, run the shell script `run.sh` in the root folder. 
To execute the unit tests, run the shell script `run_tests.sh` in the insight_testsuite folder.

File directory should look like:

├── README.md 
├── run.sh
├── src
│   └── process_log.py
|   └── helper_functions.py
├── log_input
│   └── log.txt
├── log_output
|   └── hosts.txt
|   └── hours.txt
|   └── resources.txt
|   └── blocked.txt
├── insight_testsuite
    └── run_tests.sh
    └── tests
        └── test1
        |   ├── log_input
        |   │   └── log.txt
        |   |__ log_output
        |   │   └── hosts.txt
        |   │   └── hours.txt
        |   │   └── resources.txt
        |   │   └── blocked.txt
        ├── test2
            ├── log_input
            │   └── log.txt
            |__ log_output
                └── hosts.txt
                └── hours.txt
                └── resources.txt
                └── blocked.txt

Four features calculating top 10 most frequent IP addresses, top 10 resources with the largest bandwith, top 10 busiest 60-minute time periods, and a log of blocked logins applying the stated blocking policy from the Insight challenge. 

Additional features include:
* Error logging for Unicode Decode Errors and invalid filepaths. (Uncomment relevant section in process_log.py to    generate error log txt file)
* Streaming-friendly data ingestion pipeline.
* Scalability analysis given data subsets.
* Additional unit tests for code QA.
  
Scalability Analysis:

After performing 70 tests with varying subset sizes of the data, the solution processed the data and generated the features with an average speed of 28,363.37 lines/sec. Across the trials, the solution ran in O(N) time. This indicates that the marginal cost borne by each extra minute of processing supports an extra 1,701,802 lines of data. Given that the highest minute of activity within the log.txt file was 974 logins/minute, this represents a comfortable margin to handle the current level of streaming traffic and consider scaling up operations.

* ![Scalability Analysis](./scale_analysis.png)
