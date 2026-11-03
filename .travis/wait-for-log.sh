#!/bin/sh
# Seal: Travis archives job logs asynchronously, minutes behind the job. The
# sealing harness fetches each job's log as soon as the build finishes, so a
# lagging archive yields a log cut off before the test results. Keep the job
# open (after_script cannot change the build result) until this job's own
# public log contains the script phase's result line, capped at 40 minutes.
url="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
pattern='The command .* exited with [0-9]'
i=0
while [ "$i" -lt 120 ]; do
	if curl -sfL "$url" 2>/dev/null | grep -q "$pattern"; then
		echo "wait-for-log: job log archived through the script phase"
		exit 0
	fi
	i=$((i + 1))
	sleep 20
done
echo "wait-for-log: gave up waiting for the archived log"
exit 0
