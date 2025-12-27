control 'SV-18884' do
  title 'VTC system and endpoint users, administrators, and helpdesk representatives must receive cybersecurity training.'
  desc 'All users and administrators of VTC systems and endpoints must receive training covering the vulnerabilities and other cybersecurity issues associated with operating a VTC system or endpoint. Users and administrators must be trained in the proper configuration, installation techniques, and approved connections for the VTC system or endpoint applicable to their exposure to the system. Also, users and administrators must be trained in the proper operating procedures for the system so that meeting information is properly protected and other non-meeting related information in the area near a VTC endpoint is not improperly disclosed or compromised. Helpdesk representatives supporting a VTC system or endpoints must also be appropriately trained in all aspects of VTC operation and cybersecurity. Without proper and periodic training to those directly responsible for VTC and VTU equipment and applications could lead to improper use and eventually lead to the disclosure of sensitive or classified information.'
  desc 'check', 'Review site documentation to confirm the VTC system and endpoint users, administrators, and helpdesk representatives receive cybersecurity training as follows:
 - Administrators, helpdesk representatives, and users are trained in all VTC system and endpoint vulnerabilities, cybersecurity issues, risks to both meeting and non-meeting related information, and assured service capabilities.
 - Users, administrators, and helpdesk representatives are trained in all aspects of VTC system and endpoint vulnerability, risk mitigation, and operating procedures. This training may be tailored to the specific VTC system or devices for a site.
 - Administrators and helpdesk representatives are trained in all aspects of VTC system and endpoint configuration and implementation to include approved connections.
 - The details contained in the SOPs intended to mitigate the vulnerabilities and risks associated with the configuration and operation of the specific VTC system or devices to include:
 > Protection of the information discussed or presented in the meeting such as the technical measures to prevent disclosure as well as the inadvertent disclosure of sensitive or classified information to individuals within view or earshot of the VTU.
 >The inadvertent disclosure of non-meeting related information to other conference attendees while sharing a presentation or other information from a PC workstation.
 >The inadvertent capture and dissemination of non-meeting related information from the area around the VTC endpoint to the other conference attendees.
 - Other training topics mentioned elsewhere in this document, are not listed here.

If VTC system and endpoint users, administrators, and helpdesk representatives do not receive the above cybersecurity training, this is a finding.

Note: Documentation is maintained regarding users, administrators, and helpdesk representative’s receipt of training. Training is refreshed annually and may be incorporated into other IA training received annually. The site may modify these items in accordance with local site policy however these items must be addressed in the training materials.'
  desc 'fix', 'Implement site documentation to support the VTC system and endpoint users, administrators, and helpdesk representatives receive cybersecurity training as follows:
 - Administrators, helpdesk representatives, and users are trained in all VTC system and endpoint vulnerabilities, cybersecurity issues, risks to both meeting and non-meeting related information, and assured service capabilities.
 - Users, administrators, and helpdesk representatives are trained in all aspects of VTC system and endpoint vulnerability, risk mitigation, and operating procedures. This training may be tailored to the specific VTC system or devices for a site.
 - Administrators and helpdesk representatives are trained in all aspects of VTC system and endpoint configuration and implementation to include approved connections.
 - The details contained in the SOPs intended to mitigate the vulnerabilities and risks associated with the configuration and operation of the specific VTC system or devices to include:
 > Protection of the information discussed or presented in the meeting such as the technical measures to prevent disclosure as well as the inadvertent disclosure of sensitive or classified information to individuals within view or earshot of the VTU.
 >The inadvertent disclosure of non-meeting related information to other conference attendees while sharing a presentation or other information from a PC workstation.
 >The inadvertent capture and dissemination of non-meeting related information from the area around the VTC endpoint to the other conference attendees.
 - Other training topics mentioned elsewhere in this document, are not listed here.
 Maintain documentation on who received training and when.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18980r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17710'
  tag rid: 'SV-18884r2_rule'
  tag stig_id: 'RTS-VTC 3660.00'
  tag gtitle: 'RTS-VTC 3660'
  tag fix_id: 'F-17607r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Other']
end
