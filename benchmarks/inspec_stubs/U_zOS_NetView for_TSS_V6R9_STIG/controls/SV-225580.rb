control 'SV-225580' do
  title 'NetView configuration/parameter values must be specified properly.'
  desc 'NetView configuration/parameters control the security and operational characteristics of products. If these parameter values are improperly specified, security and operational controls may be weakened. This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Review the member CxxSTYLE in the DSIPARM DD statement concatenation of the NetView CNMPROC STC procedure.

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZNET0040)

Ensure that all NetView configuration requirements are specified. If the following guidance is true, this is not a finding.

Keyword                           Value
SECOPTS.OPERSEC         SAFCHECK|SAFDEF
SECOPTS.CMDAUTH      SAF.FAIL|SAF.table'
  desc 'fix', "The Systems Programmer and ISSO will review NetView configuration parameters and control options for compliance.

To ensure authentication of users to NetView, ensure that CxxSTYLE in the DSIPARM DD statement concatenation of the NetView CNMPROC STC procedure has the following initialization parameter(s) specified:

(Note: The data set identified above is an example of a possible installation. The data set is determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

SECOPTS.OPERSEC=SAFCHECK|SAFDEF

When SECOPTS.OPERSEC=SAFCHECK is used, it specifies that operator identification and password or password phrase checking is performed using an SAF security product. The operator identifier must also be defined in DSIOPF, and other attributes given to the operator at logon are taken from the specified profile for the operator in DSIPRF.

Security access checks are checked against the authority of the operator that occur when an operator tries to access a data set that is protected in the DATASET class of an SAF product or an MVS system command that is protected in the OPERCMDS class of an SAF product.

When SECOPTS.OPERSEC=SAFDEF is used, it specifies that operator identification and password or password phrase checking is done using an SAF security product. Authority to log on as a NetView operator is controlled through the APPL class. The operator identifier must be authorized to the resource name in the APPL class which represents the NetView program.

The attributes given to the operator at logon are defined in the NETVIEW segment of the user profile for the operator in the SAF product. For more information, refer to IBM Tivoli NetView for z/OS Security Reference.

When SECOPTS.OPERSEC=SAFDEF is specified, any value for SECOPTS.CMDAUTH can be used.

Additional details can be obtained in the IBM Tivoli NetView for z/OS Security Reference.

SECOPTS.CMDAUTH=SAF.FAIL|SAF.table

When SECOPTS.CMDAUTH=SAF.table is used, table specifies the backup table to be used for immediate commands and when the SAF product cannot make a security decision. This can occur when:

___	No resource name is defined in the NETCMDS class which protects or authorizes this command.
___	The NETCMDS class is not active.
___	The security product is not active.

When SECOPTS.CMDAUTH=SAF.FAIL is used, command authority checking will fail if the SAF product can reach no decision.

Additional details can be obtained in the IBM Tivoli NetView for z/OS Administration Reference."
  impact 0.5
  ref 'DPMS Target zOS NetView for TSS'
  tag check_id: 'C-27279r868745_chk'
  tag severity: 'medium'
  tag gid: 'V-225580'
  tag rid: 'SV-225580r868747_rule'
  tag stig_id: 'ZNET0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-27267r868746_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-28492']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
