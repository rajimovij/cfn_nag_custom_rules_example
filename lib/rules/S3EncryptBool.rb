# frozen_string_literal: true

require 'cfn-nag/violation'
require_relative 'boolean_base_rule'

class EFSFileSystemEncryptedRule < BooleanBaseRule
  def rule_text
    'S3 should have encryption enabled'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'T32'
  end

  def resource_type
    'AWS::S3::Bucket'
  end

  def boolean_property
    :BucketEncryption
  end
end
