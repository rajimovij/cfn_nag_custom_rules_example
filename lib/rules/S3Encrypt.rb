{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Calibri;}}
{\*\generator Riched20 10.0.17134}\viewkind4\uc1 
\pard\sa200\sl276\slmult1\f0\fs22\lang9 # frozen_string_literal: true\par
\par
require 'cfn-nag/violation'\par
require_relative 'base'\par
\par
class IamPolicyforS3Encryption < BaseRule\par
  def rule_text\par
    'IamPolicyforS3Encryption'\par
  end\par
\par
  def rule_type\par
    Violation::WARNING\par
  end\par
\par
  def rule_id\par
    'T16'\par
  end\par
\par
  def audit_impl(cfn_model)\par
    violating_policies = cfn_model.resources_by_type('AWS::IAM::Policy')\par
                                  .select do |policy|\par
      !policy.policy_document.condition.string_not_equals == 'x-amz-server-side-encryption: AES256'\par
end\par
    violating_policies.map(&:logical_resource_id)\par
  end\par
end\par
}
 