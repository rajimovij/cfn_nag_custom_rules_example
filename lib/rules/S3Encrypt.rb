# frozen_string_literal: true
	

	require 'cfn-nag/violation'
	require_relative 'base'
	

	class IamPolicyNotActionRuleT16 < BaseRule
	  def rule_text
	    'IAM policy should not allow Allow+NotActionT16'
	  end
	

	  def rule_type
	    Violation::WARNING
	  end
	

	  def rule_id
	    'T16'
	  end
	

	  def audit_impl(cfn_model)
	       violating_policies = cfn_model.resources_by_type('AWS::IAM::Policy')
                                 .select do |policy|
      !policy.policy_document.condition.StringNotEquals == 'x-amz-server-side-encryption\: AES256'
	    end

	

	    violating_policies.map(&:logical_resource_id)
	  end
	end
