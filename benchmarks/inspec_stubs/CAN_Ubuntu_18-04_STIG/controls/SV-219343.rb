control 'SV-219343' do
  title 'The Ubuntu operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to the Ubuntu operating system performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:
     $ sudo dpkg -l | grep aide 
     ii   aide   0.16-3ubuntu0.1   amd64   Advanced Intrusion Detection Environment - static binary

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:
     $ sudo aide.wrapper --check

If the output is "Couldn't open file /var/lib/aide/aide.db for reading", this is a finding.)
  desc 'fix', 'Install AIDE, initialize it, and perform a manual check.

Install AIDE:
     $ sudo apt install aide

Initialize it (this may take a few minutes):
     $ sudo aideinit
     Running aide --init...

Example output:

     Start timestamp: 2022-11-20 11:53:17 -0700 (AIDE 0.16)
     AIDE initialized database at /var/lib/aide/aide.db.new
     Verbose level: 6

     Number of entries:      119543

     ---------------------------------------------------
     The attributes of the (uncompressed) database(s):
     ---------------------------------------------------

     /var/lib/aide/aide.db.new
     RMD160   : PiEP1DX91JMcHnRSPnpFqNfIFr4=
     TIGER    : /zM5yQBnOIoEH0jplJE5v6S0rUErbTXL
     SHA256   : BE2iHtBN9lEX53l4R/p7t1al0dIlsgPc
                       Lg4YI08+/Jk=
     SHA512   : JIdGeNVRgtBPPSwun9St+9cwUrgIIKUW
                       KVTksZXJ29Tt+luC/XNDcjIub7fbPVw/
                       EcTDsvYtt9MBmBxw1wCYng==
     CRC32    : jB2FVw==
     HAVAL    : Jhe+fqaDpkswpWSnOTN28TO05QFHsjdq
                       RcFZwCVUGTQ=
     GOST     : WFrarVyxpXbKdW9SAaOy1Te8rSodV3/q
                     nLsXuP7YujA=


End timestamp: 2022-11-20 11:58:19 -0700 (run time: 5m 2s)

The new database will need to be renamed to be read by AIDE:
     $ sudo cp -p /var/lib/aide/aide.db.new /var/lib/aide/aide.db

Perform a manual check:
     $ sudo aide.wrapper --check

Example output:
     Start timestamp: 2022-11-20 11:59:16 -0700 (AIDE 0.16)
     AIDE found differences between database and filesystem!!
     ...
	 
Done.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21068r880895_chk'
  tag severity: 'medium'
  tag gid: 'V-219343'
  tag rid: 'SV-219343r880897_rule'
  tag stig_id: 'UBTU-18-010515'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-21067r880896_fix'
  tag 'documentable'
  tag legacy: ['V-100907', 'SV-110011']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
