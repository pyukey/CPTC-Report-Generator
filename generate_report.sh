#!/bin/sh

REPORT_FINDING_DIR="../report/content/technicalReport/findings/"
REPORT_IMAGE_DIR="../report/images/findings/"
FINDINGS_LIST_LOC="../report/content/technicalReport/allFindings.tex"
GENERATE_FINDING_SCRIPT="./generate_finding_latex.sh"
FINDINGS_LIST_SCRIPT="./generate_findings_list.sh"

cd scripts
mkdir -p $REPORT_FINDING_DIR
mkdir -p $REPORT_IMAGE_DIR

for finding_dir in ../findings/*/; do
  # Skip if not a directory
  [ -d "$finding_dir" ] || continue

  $GENERATE_FINDING_SCRIPT $finding_dir $REPORT_FINDING_DIR $REPORT_IMAGE_DIR
done

sort -ur ../scores.tmp > ../scores.txt
rm ../scores.tmp

${FINDINGS_LIST_SCRIPT} > ${FINDINGS_LIST_LOC}
