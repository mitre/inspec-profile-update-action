control 'SV-223689' do
  title 'IBM z/OS MCS consoles access authorization(s) for CONSOLE resource(s) must be properly protected.'
  desc 'MCS consoles can be used to issue operator commands. Failure to properly control access to MCS consoles could result in unauthorized personnel issuing sensitive operator commands. This exposure may threaten the integrity and availability of the operating system environment, and compromise the confidentiality of customer data.

Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

'
  desc 'check', 'Verify the CONSOLxx member of SYS1.PARMLIB.console is defined to RACF with a corresponding profile in the CONSOLE resource class.

If each console is defined to RACF with a corresponding profile in the CONSOLE resource class, this is not a finding.

If the userid associated with each console has READ access to the corresponding resource defined in the CONSOLE resource class, this is not a finding.

If access authorization for CONSOLE resources restricts READ access to operations and system programming personnel or authorized personnel, this is not a finding.'
  desc 'fix', 'Define all MCS consoles to the CONSOLE resource class and configure READ access to be limited to operators and system programmers.

Configure the MCS console resources defined to z/OS and the ESM to conform to those outlined below.

Each console defined in the CONSOLxx parmlib member is defined to RACF with a corresponding profile in the CONSOLE resource class. See the IBM zOS OPERATIONS AND PLANNING guide for further information.

Each CONSOLE profile is defined with UACC(NONE). 

Example:
RDEF CONSOLE MMDMST UACC(NONE) OWNER(syspsmpl) 
RDEF CONSOLE MMD041 UACC(NONE) OWNER(syspsmpl) 
RDEF CONSOLE MMDSCN UACC(NONE) OWNER(syspsmpl)
RDEF CONSOLE ** UACC(NONE) OWNER(syspsmpl) DATA(** represents all consoles not specifically defined)

Do not permit any user or group access to the ** profile. If a new console is added to the CONSOLxx member it will be covered by this profile and a subsequent error will display in the log, which will allow identification of the undefined console.

The userid associated with each console will have READ access to the corresponding resource defined in the CONSOLE resource class. A sample command file to accomplish this is shown here:

PE MMDMST CL(CONSOLE) ID(mmdmst)
PE MMDSCN CL(CONSOLE) ID(mmdscn)
PE MMD041 CL(CONSOLE) ID(mmd041)

Access authorization for CONSOLE resources restricts READ access to operations and system programming personnel or authorized personnel. A sample command file showing a permission of READ access for sysprogs and operators is shown here:

PE MMDMST CL(CONSOLE) ID(syspsmpl opersmpl)
PE MMDSCN CL(CONSOLE) ID(syspsmpl opersmpl)
PE MMD041 CL(CONSOLE) ID(syspsmpl opersmpl)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25362r816947_chk'
  tag severity: 'medium'
  tag gid: 'V-223689'
  tag rid: 'SV-223689r816949_rule'
  tag stig_id: 'RACF-ES-000410'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25350r816948_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98083', 'SV-107187']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
