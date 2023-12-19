control 'SV-239124' do
  title 'The Photon operating system package files must not be modified.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Without confidence in the integrity of the auditing system and tools, the information it provides cannot be trusted.'
  desc 'check', 'Use the verification capability of rpm to check the MD5 hashes of the audit files on disk versus the expected ones from the installation package. 

At the command line, execute the following command:

# rpm -V audit | grep "^..5" | grep -v "^...........c"

If there is output, this is a finding.'
  desc 'fix', 'If the audit system binaries have been altered, the system must be taken offline and the ISSM must be notified immediately. 

Reinstalling the audit tools is not supported. 

The appliance should be restored from a backup or a snapshot or redeployed once the root cause is remediated.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42335r675178_chk'
  tag severity: 'medium'
  tag gid: 'V-239124'
  tag rid: 'SV-239124r675180_rule'
  tag stig_id: 'PHTN-67-000053'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-42294r675179_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
