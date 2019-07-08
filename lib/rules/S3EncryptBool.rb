require 'cfn-nag/violation'
require_relative 'boolean_base_rule'

class ElasticIPNotAllowedRule < BooleanBaseRule

  def rule_text
    'Elastic IP should not be assigned'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'WU11111'
  end

  def resource_type
    ''AWS::IAM::Policy'
  end

  def boolean_property
    :AES256
  end
end
