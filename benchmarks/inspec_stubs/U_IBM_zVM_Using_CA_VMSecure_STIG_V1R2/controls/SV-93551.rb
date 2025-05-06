control 'SV-93551' do
  title 'CA VM:Secure product must be installed and operating.'
  desc 'A comprehensive account management process such as provided by an External Security Manager (ESM) which includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed.

Account management functions include: assigning group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts.

Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

'
  desc 'check', 'Verify the CA VM:Secure product is operational on the system by entering the following command.

From the “CMS” command line enter:

VMSECURE VERSION

If there is no response, "VMSECURE" is not logged in, this is a finding.'
  desc 'fix', 'CA VM:Secure product audits all commands.

Ensure CA VM:Secure product is installed and operational.

Using CA VM:Secure product audit of all commands with z/VM standard journal record assures that all pertinent information is stored.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78431r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78845'
  tag rid: 'SV-93551r1_rule'
  tag stig_id: 'IBMZ-VM-000030'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-85595r1_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000032-GPOS-00013', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000477-GPOS-00222', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000465-GPOS-00209']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-001487', 'CCI-001814', 'CCI-002130', 'CCI-002234', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AC-17 (1)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-3 f', 'CM-5 (1)', 'AC-2 (4)', 'AC-6 (9)', 'MA-4 (1) (a)']
end
