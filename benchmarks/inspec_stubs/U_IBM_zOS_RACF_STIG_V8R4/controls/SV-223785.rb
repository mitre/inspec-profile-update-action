control 'SV-223785' do
  title 'IBM zOS inapplicable PPT entries must be invalidated.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Invalid or inapplicable PPT entries exist, a venue is provided for the introduction of trojan horse modules with security bypass capabilities.'
  desc 'check', 'Review program entries in the IBM Program Properties Table (PPT). You may use a third-party product to examine these entries however, to determine program entries issue the following command from an ISPF command line enter:
TSO ISRDDN LOAD IEFSDPPT

Interpret the display as follows:
Examine contents at offset 8 
Hex ‘x2’ - Bypass Password Protection 
Hex ‘x3’ - Bypass Password Protection
Hex ‘x4’ - No Dataset Integrity
Hex ‘x5’ - No Dataset Integrity
Hex ‘x6’ - Both
Hex ‘x7’ - Both 

Determine Privilege Key at offset 9. A value of hex ’70’ or less indicates an elevated privilege.

For each module identified in the "eyecatcher" that has BYPASS Password Protection, No Dataset Integrity, an elevated Privilege Key or any combination thereof, determine if there is a valid loaded module. Again, you may use a third-party product otherwise execute the following steps from an ISPF command line enter:
TSO ISRDDN LOAD <privileged module>

If the return message is "Load Failed" make sure there is an entry in PARMLIB member SCHEDxx that revokes the excessive privilege.

If this is not true, this is a finding.'
  desc 'fix', "Review the PPT and define all entries associated with non-existent or inapplicable modules as invalidated. Nullify the invalid IEFSDPPT entry by ensuring that there is a corresponding SCHED entry, which confers no special attributes. 

Use the following recommendations and techniques to provide protection for the PPT:

Review the IEFSDPPT module and all programs that IBM has, by default, placed in the PPT to validate their applicability to the execution system. Refer to the IBM z/OS MVS Initialization and Tuning Reference documentation for the version and release of z/OS installed at the individual site for the actual contents of the default IEFSDPPT. 

Modules for products not in use on the system will have their special privileges explicitly revoked. Do this by placing a PPT entry for each module in the SYS1.PARMLIB(SCHEDxx) member, specifying no special privileges. The PPT entry for each overridden program will be in the following format, accepting the default (unprivileged) values for the sub parameters:

PPT PGMNAME(<program name>)

Assemble documentation regarding these PPT entries, and the ISSO will keep it on file. Include the following in the documentation:

- The product and release for which the PPT entry was made
- The last date this entry was reviewed to authenticate status
- The reason the module's privileges are being revoked"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25458r515043_chk'
  tag severity: 'medium'
  tag gid: 'V-223785'
  tag rid: 'SV-223785r604139_rule'
  tag stig_id: 'RACF-OS-000290'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-25446r515044_fix'
  tag 'documentable'
  tag legacy: ['V-98277', 'SV-107381']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
