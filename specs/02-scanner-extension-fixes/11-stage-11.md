### Stage 11 (Tests): Extension Display All Sections

**Goal**: Write tests to verify extension displays all result sections, not just one based on scan type.

#### Checklist

[ ] Test extension shows multiple sections
  - When scanning CloudFormation with IAM + S3 + SG resources
  - Verify output contains all three section headers
  - Verify each section shows correct count

[ ] Test extension shows iam_policies section
  - When scanning IAM policy file
  - Verify "IAM Policies:" header appears
  - Verify policy name displayed correctly

[ ] Test extension doesn't show empty sections
  - When scanning S3 file
  - Verify only S3 section appears
  - Verify IAM sections not shown if empty
