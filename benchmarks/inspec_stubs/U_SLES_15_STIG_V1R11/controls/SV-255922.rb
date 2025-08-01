control 'SV-255922' do
  title 'The SUSE operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to the SUSE operating system performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:
     $ sudo zypper if aide | grep "Installed"
     Installed: Yes

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:
     $ sudo aide --check

If the output is "Couldn't open file /var/lib/aide/aide.db for reading", this is a finding.)
  desc 'fix', 'Install AIDE, initialize it, and perform a manual check.

Install AIDE:
     $ sudo zipper in aide

Initialize it (this may take a few minutes):
     $ sudo aide -i

The new database will need to be renamed to be read by AIDE:
     $ sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

Perform a manual check:
     $ sudo aide --check

Example output:
     Summary:
       Total number of files:        140621
       Added files:                  1
       Removed files:                1
       Changed files:                0

Done.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-59599r880965_chk'
  tag severity: 'medium'
  tag gid: 'V-255922'
  tag rid: 'SV-255922r880967_rule'
  tag stig_id: 'SLES-15-010419'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-59542r880966_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
