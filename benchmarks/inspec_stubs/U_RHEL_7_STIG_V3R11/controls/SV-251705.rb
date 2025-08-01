control 'SV-251705' do
  title 'The Red Hat Enterprise Linux operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to the Red Hat Enterprise Linux operating system performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:
     $ sudo rpm -q aide

     aide-0.15.1-13.el7.x86_64

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:
     $ sudo /usr/sbin/aide --check

If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
  desc 'fix', 'Install AIDE, initialize it, and perform a manual check.

Install AIDE:
     $ sudo yum install aide

Initialize it:
     $ sudo /usr/sbin/aide --init

     AIDE, version 0.15.1
     ### AIDE database at /var/lib/aide/aide.db.new.gz initialized.

The new database will need to be renamed to be read by AIDE:
     $ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

Perform a manual check:
     $ sudo /usr/sbin/aide --check

     AIDE, version 0.15.1
     ### All files match AIDE database. Looks okay!

Done.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-55142r880852_chk'
  tag severity: 'medium'
  tag gid: 'V-251705'
  tag rid: 'SV-251705r880854_rule'
  tag stig_id: 'RHEL-07-020029'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-55096r880853_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
