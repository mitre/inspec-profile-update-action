control 'SV-13609' do
  title 'The IAO has not established written procedures for the process of updating zone records, who is authorized to submit and approve update requests, how the DNS administrator verifies the identity of the person from whom he/she received the request, and how the DNS administrator documents any changes made.'
  desc 'If the procedures for updating zone records are inadequate, then this increases the probability that adversary  perhaps even an insider will be able to modify the DNS records using weaknesses in administrative processes rather than weaknesses in technical controls.'
  desc 'check', 'To best assure the integrity of zone files, one must not only carefully manage the manner in which requests are processed but also periodically check that the current records are valid.  For example, when equipment is retired, people often fail to remove the associated host from the DNS.  Without periodic checks, an attacker may use a retired host IP address to obtain valuable information from another user who was unaware of the change.

Instruction:  If there are no written procedures for manual updates of zone files (e.g., a new host entry), then this is a finding.  If there are such procedures, then it must cover the following:

- The process for updating zone records
- Who is authorized to submit and approve update requests
- How the DNS database administrator verifies the identity of the person from whom he or she received the request
- How the DNS database administrator documents any changes made

This is a finding if any of these elements are missing from the procedures for manually updating zone records. *Note:  If secure dynamic updates are being utilized without any administrator interaction, then this check can be marked Not Applicable.'
  desc 'fix', 'The IAO should establish standard operating procedures for updating zone records.  These procedures should include, at a minimum, the process for updating zone records, who is authorized to submit and approve update requests, how the DNS database administrator verifies the identity of the person from whom he or she received the request, and how the DNS database administrator documents any changes made.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3364r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13041'
  tag rid: 'SV-13609r1_rule'
  tag stig_id: 'DNS0150'
  tag gtitle: 'Procedures for updating zone records'
  tag fix_id: 'F-4346r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
