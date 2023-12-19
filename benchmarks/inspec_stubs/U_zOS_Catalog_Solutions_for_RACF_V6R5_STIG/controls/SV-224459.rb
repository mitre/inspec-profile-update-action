control 'SV-224459' do
  title 'Catalog Solutions Install data sets are not properly protected.'
  desc 'Catalog Solutions is a very powerful tool that can pose risks if not properly controlled. If security is not properly implemented, the users of the product could present data integrity exposures, bypass security for catalog datasets, other VSAM files, and aliases.

Catalog Solutions Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a) Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CSLPROD)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCSL0000)

b) Verify that access to the Catalog Solutions Install data sets are properly restricted.
 
___ The RACF data set rules for the data sets does not restrict UPDATE and/or ALTER access to only systems programming personnel.

___ The RACF data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c) If all of the above are untrue, there is no finding.

d) If any of the above is true, this is a finding.'
  desc 'fix', "The ISSO will ensure that update and allocate access to program product data sets is limited to systems programmers only, unless a letter justifying access is filed with the ISSO, and all update and allocate access is logged.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have UPDATE and ALTER access and if required that all UPDATE and ALTER access is logged. The installing systems programmer will identify if any additional groups have UPDATE access for specific data sets, and once documented work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

The following commands are provided as a sample for implementing dataset controls:

ad 'sys2.csl.**' uacc(none) owner(sys2) -                           
 audit(success(update) failures(read)) -                            
 data('Catalog Solution Vendor Datasets: Ref SRR PDI ZCSLR000')    
pe 'sys2.csl.**' id(<syspaudt>) acc(a)                              
ad 'sys3.csl.**' uacc(none) owner(sys3) -                           
 audit(success(update) failures(read)) -                            
 data('Catalog Solution Customized Datasets: Ref SRR PDI ZCSLR000')
pe 'sys3.csl.**' id(<syspaudt>) acc(a)                              
setr generic(dataset) refresh                                       

Catalog Solution allows you to monitor your catalog environment to help identify and correct structural catalog problems before they create system outages. Catalog Solution is a valuable tool in planning for or implementing System Managed Storage, as well as ensuring daily system availability. Catalog Solution is a comprehensive facility for the management, maintenance, repair, and recovery of the MVS catalog environment that complements the IDC Access Method Services (IDCAMS) utility.

Catalog Solution helps you in the five key areas: Maintenance, Diagnostics, Reporting, Backup and Recovery, and SMF management.

Catalog Solution is a very powerful tool that can pose risks if not properly controlled. If security is not properly implemented, the users of the product could present data integrity exposures, bypass security for catalog datasets, other VSAM files, and aliases. As an authorized program, Catalog Solution bypasses many of the normal system security facilities - catalog and dataset passwords in particular. Improper use of Catalog Solution can result in non-synchronized catalog, dataset, or VVDS record groups. Therefore, certain commands should not be made available to the user community. As delivered, Catalog Solution bypasses dataset security checking for VSAM datasets and BCS processing. Clearly there are risks associated and valid requirements exist to ensure full external security controls are properly implemented for the Catalog Solution product.

Properly securing the use of various commands and features is crucial. All Catalog Solution functions should be reviewed for potential security exposures and to prevent unauthorized use. Some Catalog Solution functions allow for bypassing of security controls, and as such shall be restricted to systems programmers who perform in the specific role of Storage management."
  impact 0.5
  ref 'DPMS Target zOS Catalog Solutions for RACF'
  tag check_id: 'C-26136r868337_chk'
  tag severity: 'medium'
  tag gid: 'V-224459'
  tag rid: 'SV-224459r868339_rule'
  tag stig_id: 'ZCSLR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26124r868338_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-19581']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
