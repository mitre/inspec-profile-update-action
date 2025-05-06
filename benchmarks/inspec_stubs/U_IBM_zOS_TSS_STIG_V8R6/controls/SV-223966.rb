control 'SV-223966' do
  title 'CA-TSS Default ACID must be properly defined.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST STC

If *DEF* has action of *FAIL* this is not a finding.

If the default ACID is defined enter:
TSS List(<defined ACID>)

If the ACID has no access to resources and no facility access and sourced to the internal reader, this is not a finding.

If any of the above is untrue, this is a finding.'
  desc 'fix', %q(Ensure the default STC ACID is defined in accordance with the following restrictions. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as specified.

All STCs not defined to TSS will fail upon initiation. The following command may be used to associate all undefined STCs with a default action of FAIL:

TSS ADD(STC) PROCNAME(DEFAULT) ACID(FAIL)

If a valid requirement exists to establish a default STC, the following restrictions also apply:

a. The ISSO will maintain the written request, justification, and authorization.

b. The STC's ACID will have no other facilities permitted to it.

c. The STC's ACID will have a permission of DSN(*****) ACCESS(NONE).

TSS PERMIT(stc-acid) DSN(*****) ACCESS(NONE)

d. The STC's ACID will not have any permission to the resources available to TSS.

e. The STC's ACID will be sourced to the internal reader:

ADD(stc-acid) SOURCE(INTRDR)

f. An entry will be made in the STC table identifying the default ACID name as follows ("stc-acid" site defined):

TSS ADD(STC) PROCNAME(DEFAULT) ACID(stc-acid))
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25639r516297_chk'
  tag severity: 'medium'
  tag gid: 'V-223966'
  tag rid: 'SV-223966r561402_rule'
  tag stig_id: 'TSS0-ES-000930'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25627r516298_fix'
  tag 'documentable'
  tag legacy: ['V-98639', 'SV-107743']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
