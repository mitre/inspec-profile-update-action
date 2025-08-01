control 'SV-251710' do
  title 'The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to the RHEL 8 operating system performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:

$ sudo rpm -q aide

aide-0.16-14.el8.x86_64

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.'
  desc 'fix', 'Install the AIDE package by running the following command:

$ sudo yum install aide'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-55147r809352_chk'
  tag severity: 'medium'
  tag gid: 'V-251710'
  tag rid: 'SV-251710r854081_rule'
  tag stig_id: 'RHEL-08-010359'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-55101r809353_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
