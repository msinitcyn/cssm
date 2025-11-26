### Phase 2: CloudFormation Reader

[x] Research 3rd party CloudFormation parsers
  - Evaluate options (cfn-lint, pycfmodel, troposphere, others)
  - Consider: parsing capability, maintenance, dependencies

[x] Define internal CloudFormation data structure
  - Object to represent parsed CloudFormation template
  - Must capture: Resources, resource types, properties
  - Keep it simple - only what we need for extraction

[x] Create unit tests for CloudFormation reader
  - Test parsing YAML template
  - Test parsing JSON template
  - Test extracting Resources section
  - Test identifying resource types (AWS::IAM::Role, AWS::S3::Bucket, etc.)
  - Tests will fail initially (TDD)

[x] Implement CloudFormation reader
  - Parse CloudFormation YAML/JSON
  - Extract Resources section
  - Return internal data structure
  - Make unit tests pass

