import re


SOURCE_NONE = re.compile('', re.IGNORECASE)
SOURCE_SEC = re.compile('Microsoft-Windows-Security-Auditing', re.IGNORECASE)


SECURITY = {
    1102: ('Audit log was cleared. This can relate to a potential attack', SOURCE_NONE),  # nopep8
    4616: ('System time was changed', SOURCE_NONE),  # nopep8
    4624: ('Successful account log on', SOURCE_SEC),  # nopep8
    4625: ('Failed account log on', SOURCE_NONE),  # nopep8
    4634: ('An account logged off', SOURCE_SEC),  # nopep8
    4648: ('A logon attempt was made with explicit credentials', SOURCE_NONE),  # nopep8
    4657: ('A registry value was changed', SOURCE_NONE),  # nopep8
    4663: ('Attempt made to access object', SOURCE_NONE),  # nopep8
    4670: ('Permissions on an object were changed', SOURCE_NONE),  # nopep8
    4672: ('Special privileges assigned to new logon', SOURCE_SEC),  # nopep8
    4688: ('A new process has been created', SOURCE_NONE),  # nopep8
    4697: ('An attempt was made to install a service', SOURCE_NONE),  # nopep8
    4698: ('A scheduled task was created', SOURCE_NONE),  # nopep8
    4699: ('A scheduled task was deleted', SOURCE_NONE),  # nopep8
    4700: ('A scheduled task was enabled', SOURCE_NONE),  # nopep8
    4701: ('A scheduled task was disabled', SOURCE_NONE),  # nopep8
    4702: ('A scheduled task was updated', SOURCE_NONE),  # nopep8
    4719: ('System audit policy was changed.', SOURCE_NONE),  # nopep8
    4720: ('A user account was created', SOURCE_NONE),  # nopep8
    4722: ('A user account was enabled', SOURCE_NONE),  # nopep8
    4723: ('An attempt was made to change the password of an account', SOURCE_NONE),  # nopep8
    4725: ('A user account was disabled', SOURCE_NONE),  # nopep8
    4728: ('A user was added to a privileged global group', SOURCE_NONE),  # nopep8
    4732: ('A user was added to a privileged local group', SOURCE_NONE),  # nopep8
    4735: ('A privileged local group was modified', SOURCE_NONE),  # nopep8
    4737: ('A privileged global group was modified', SOURCE_NONE),  # nopep8
    4738: ('A user account was changed', SOURCE_NONE),  # nopep8
    4740: ('A user account was locked out', SOURCE_NONE),  # nopep8
    4755: ('A privileged universal group was modified', SOURCE_NONE),  # nopep8
    4756: ('A user was added to a privileged universal group', SOURCE_NONE),  # nopep8
    4767: ('A user account was unlocked', SOURCE_NONE),  # nopep8
    4772: ('A Kerberos authentication ticket request failed', SOURCE_NONE),  # nopep8
    4777: ('The domain controller failed to validate the credentials of an account.', SOURCE_NONE),  # nopep8
    4782: ('Password hash an account was accessed', SOURCE_NONE),  # nopep8
    4946: ('A rule was added to the Windows Firewall exception list', SOURCE_NONE),  # nopep8
    4947: ('A rule was modified in the Windows Firewall exception list', SOURCE_NONE),  # nopep8
    4950: ('A setting was changed in Windows Firewall', SOURCE_NONE),  # nopep8
    4954: ('Group Policy settings for Windows Firewall has changed', SOURCE_NONE),  # nopep8
    4964: ('A special group has been assigned to a new log on', SOURCE_NONE),  # nopep8
    5025: ('The Windows Firewall service has been stopped', SOURCE_NONE),  # nopep8
    5031: ('Windows Firewall blocked an application from accepting incoming traffic', SOURCE_NONE),  # nopep8
    5152: ('A network packet was blocked by Windows Filtering Platform', SOURCE_NONE),  # nopep8
    5153: ('A network packet was blocked by Windows Filtering Platform', SOURCE_NONE),  # nopep8
    5155: ('Windows Filtering Platform blocked an application or service from listening on a port', SOURCE_NONE),  # nopep8
    5157: ('Windows Filtering Platform blocked a connection', SOURCE_NONE),  # nopep8
    5447: ('A Windows Filtering Platform filter was changed', SOURCE_NONE),  # nopep8
    36871: ('A fatal error occurred while creating a TLS client or server credential', SOURCE_NONE),  # nopep8
}

WINDOWS = {
    1100: ('The event logging service has shut down', SOURCE_NONE),  # nopep8
    1101: ('Audit events have been dropped by the transport.', SOURCE_NONE),  # nopep8
    1102: ('The audit log was cleared', SOURCE_NONE),  # nopep8
    1104: ('The security Log is now full', SOURCE_NONE),  # nopep8
    1105: ('Event log automatic backup', SOURCE_NONE),  # nopep8
    1108: ('The event logging service encountered an error', SOURCE_NONE),  # nopep8
    4608: ('Windows is starting up', SOURCE_NONE),  # nopep8
    4609: ('Windows is shutting down', SOURCE_NONE),  # nopep8
    4610: ('An authentication package has been loaded by the Local Security Authority', SOURCE_NONE),  # nopep8
    4611: ('A trusted logon process has been registered with the Local Security Authority', SOURCE_NONE),  # nopep8
    4612: ('Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.', SOURCE_NONE),  # nopep8
    4614: ('A notification package has been loaded by the Security Account Manager.', SOURCE_NONE),  # nopep8
    4615: ('Invalid use of LPC port', SOURCE_NONE),  # nopep8
    4616: ('The system time was changed.', SOURCE_NONE),  # nopep8
    4618: ('A monitored security event pattern has occurred', SOURCE_NONE),  # nopep8
    4621: ('Administrator recovered system from CrashOnAuditFail', SOURCE_NONE),  # nopep8
    4622: ('A security package has been loaded by the Local Security Authority.', SOURCE_NONE),  # nopep8
    4624: ('An account was successfully logged on', SOURCE_SEC),  # nopep8
    4625: ('An account failed to log on', SOURCE_NONE),  # nopep8
    4626: ('User/Device claims information', SOURCE_NONE),  # nopep8
    4627: ('Group membership information.', SOURCE_NONE),  # nopep8
    4634: ('An account was logged off', SOURCE_SEC),  # nopep8
    4646: ('IKE DoS-prevention mode started', SOURCE_NONE),  # nopep8
    4647: ('User initiated logoff', SOURCE_NONE),  # nopep8
    4648: ('A logon was attempted using explicit credentials', SOURCE_NONE),  # nopep8
    4649: ('A replay attack was detected', SOURCE_NONE),  # nopep8
    4650: ('An IPsec Main Mode security association was established', SOURCE_NONE),  # nopep8
    4651: ('An IPsec Main Mode security association was established', SOURCE_NONE),  # nopep8
    4652: ('An IPsec Main Mode negotiation failed', SOURCE_NONE),  # nopep8
    4653: ('An IPsec Main Mode negotiation failed', SOURCE_NONE),  # nopep8
    4654: ('An IPsec Quick Mode negotiation failed', SOURCE_NONE),  # nopep8
    4655: ('An IPsec Main Mode security association ended', SOURCE_NONE),  # nopep8
    4656: ('A handle to an object was requested', SOURCE_NONE),  # nopep8
    4657: ('A registry value was modified', SOURCE_NONE),  # nopep8
    4658: ('The handle to an object was closed', SOURCE_NONE),  # nopep8
    4659: ('A handle to an object was requested with intent to delete', SOURCE_NONE),  # nopep8
    4660: ('An object was deleted', SOURCE_NONE),  # nopep8
    4661: ('A handle to an object was requested', SOURCE_NONE),  # nopep8
    4662: ('An operation was performed on an object', SOURCE_NONE),  # nopep8
    4663: ('An attempt was made to access an object', SOURCE_NONE),  # nopep8
    4664: ('An attempt was made to create a hard link', SOURCE_NONE),  # nopep8
    4665: ('An attempt was made to create an application client context.', SOURCE_NONE),  # nopep8
    4666: ('An application attempted an operation', SOURCE_NONE),  # nopep8
    4667: ('An application client context was deleted', SOURCE_NONE),  # nopep8
    4668: ('An application was initialized', SOURCE_NONE),  # nopep8
    4670: ('Permissions on an object were changed', SOURCE_NONE),  # nopep8
    4671: ('An application attempted to access a blocked ordinal through the TBS', SOURCE_NONE),  # nopep8
    4672: ('Special privileges assigned to new logon', SOURCE_SEC),  # nopep8
    4673: ('A privileged service was called', SOURCE_NONE),  # nopep8
    4674: ('An operation was attempted on a privileged object', SOURCE_NONE),  # nopep8
    4675: ('SIDs were filtered', SOURCE_NONE),  # nopep8
    4688: ('A new process has been created', SOURCE_NONE),  # nopep8
    4689: ('A process has exited', SOURCE_NONE),  # nopep8
    4690: ('An attempt was made to duplicate a handle to an object', SOURCE_NONE),  # nopep8
    4691: ('Indirect access to an object was requested', SOURCE_NONE),  # nopep8
    4692: ('Backup of data protection master key was attempted', SOURCE_NONE),  # nopep8
    4693: ('Recovery of data protection master key was attempted', SOURCE_NONE),  # nopep8
    4694: ('Protection of auditable protected data was attempted', SOURCE_NONE),  # nopep8
    4695: ('Unprotection of auditable protected data was attempted', SOURCE_NONE),  # nopep8
    4696: ('A primary token was assigned to process', SOURCE_NONE),  # nopep8
    4697: ('A service was installed in the system', SOURCE_NONE),  # nopep8
    4698: ('A scheduled task was created', SOURCE_NONE),  # nopep8
    4699: ('A scheduled task was deleted', SOURCE_NONE),  # nopep8
    4700: ('A scheduled task was enabled', SOURCE_NONE),  # nopep8
    4701: ('A scheduled task was disabled', SOURCE_NONE),  # nopep8
    4702: ('A scheduled task was updated', SOURCE_NONE),  # nopep8
    4703: ('A token right was adjusted', SOURCE_NONE),  # nopep8
    4704: ('A user right was assigned', SOURCE_NONE),  # nopep8
    4705: ('A user right was removed', SOURCE_NONE),  # nopep8
    4706: ('A new trust was created to a domain', SOURCE_NONE),  # nopep8
    4707: ('A trust to a domain was removed', SOURCE_NONE),  # nopep8
    4709: ('IPsec Services was started', SOURCE_NONE),  # nopep8
    4710: ('IPsec Services was disabled', SOURCE_NONE),  # nopep8
    4711: ('PAStore Engine (1%)', SOURCE_NONE),  # nopep8
    4712: ('IPsec Services encountered a potentially serious failure', SOURCE_NONE),  # nopep8
    4713: ('Kerberos policy was changed', SOURCE_NONE),  # nopep8
    4714: ('Encrypted data recovery policy was changed', SOURCE_NONE),  # nopep8
    4715: ('The audit policy (SACL) on an object was changed', SOURCE_NONE),  # nopep8
    4716: ('Trusted domain information was modified', SOURCE_NONE),  # nopep8
    4717: ('System security access was granted to an account', SOURCE_NONE),  # nopep8
    4718: ('System security access was removed from an account', SOURCE_NONE),  # nopep8
    4719: ('System audit policy was changed', SOURCE_NONE),  # nopep8
    4720: ('A user account was created', SOURCE_NONE),  # nopep8
    4722: ('A user account was enabled', SOURCE_NONE),  # nopep8
    4723: ('An attempt was made to change an account\'s password', SOURCE_NONE),  # nopep8
    4724: ('An attempt was made to reset an accounts password', SOURCE_NONE),  # nopep8
    4725: ('A user account was disabled', SOURCE_NONE),  # nopep8
    4726: ('A user account was deleted', SOURCE_NONE),  # nopep8
    4727: ('A security-enabled global group was created', SOURCE_NONE),  # nopep8
    4728: ('A member was added to a security-enabled global group', SOURCE_NONE),  # nopep8
    4729: ('A member was removed from a security-enabled global group', SOURCE_NONE),  # nopep8
    4730: ('A security-enabled global group was deleted', SOURCE_NONE),  # nopep8
    4731: ('A security-enabled local group was created', SOURCE_NONE),  # nopep8
    4732: ('A member was added to a security-enabled local group', SOURCE_NONE),  # nopep8
    4733: ('A member was removed from a security-enabled local group', SOURCE_NONE),  # nopep8
    4734: ('A security-enabled local group was deleted', SOURCE_NONE),  # nopep8
    4735: ('A security-enabled local group was changed', SOURCE_NONE),  # nopep8
    4737: ('A security-enabled global group was changed', SOURCE_NONE),  # nopep8
    4738: ('A user account was changed', SOURCE_NONE),  # nopep8
    4739: ('Domain Policy was changed', SOURCE_NONE),  # nopep8
    4740: ('A user account was locked out', SOURCE_NONE),  # nopep8
    4741: ('A computer account was created', SOURCE_NONE),  # nopep8
    4742: ('A computer account was changed', SOURCE_NONE),  # nopep8
    4743: ('A computer account was deleted', SOURCE_NONE),  # nopep8
    4744: ('A security-disabled local group was created', SOURCE_NONE),  # nopep8
    4745: ('A security-disabled local group was changed', SOURCE_NONE),  # nopep8
    4746: ('A member was added to a security-disabled local group', SOURCE_NONE),  # nopep8
    4747: ('A member was removed from a security-disabled local group', SOURCE_NONE),  # nopep8
    4748: ('A security-disabled local group was deleted', SOURCE_NONE),  # nopep8
    4749: ('A security-disabled global group was created', SOURCE_NONE),  # nopep8
    4750: ('A security-disabled global group was changed', SOURCE_NONE),  # nopep8
    4751: ('A member was added to a security-disabled global group', SOURCE_NONE),  # nopep8
    4752: ('A member was removed from a security-disabled global group', SOURCE_NONE),  # nopep8
    4753: ('A security-disabled global group was deleted', SOURCE_NONE),  # nopep8
    4754: ('A security-enabled universal group was created', SOURCE_NONE),  # nopep8
    4755: ('A security-enabled universal group was changed', SOURCE_NONE),  # nopep8
    4756: ('A member was added to a security-enabled universal group', SOURCE_NONE),  # nopep8
    4757: ('A member was removed from a security-enabled universal group', SOURCE_NONE),  # nopep8
    4758: ('A security-enabled universal group was deleted', SOURCE_NONE),  # nopep8
    4759: ('A security-disabled universal group was created', SOURCE_NONE),  # nopep8
    4760: ('A security-disabled universal group was changed', SOURCE_NONE),  # nopep8
    4761: ('A member was added to a security-disabled universal group', SOURCE_NONE),  # nopep8
    4762: ('A member was removed from a security-disabled universal group', SOURCE_NONE),  # nopep8
    4763: ('A security-disabled universal group was deleted', SOURCE_NONE),  # nopep8
    4764: ('A groups type was changed', SOURCE_NONE),  # nopep8
    4765: ('SID History was added to an account', SOURCE_NONE),  # nopep8
    4766: ('An attempt to add SID History to an account failed', SOURCE_NONE),  # nopep8
    4767: ('A user account was unlocked', SOURCE_NONE),  # nopep8
    4768: ('A Kerberos authentication ticket (TGT) was requested', SOURCE_NONE),  # nopep8
    4769: ('A Kerberos service ticket was requested', SOURCE_NONE),  # nopep8
    4770: ('A Kerberos service ticket was renewed', SOURCE_NONE),  # nopep8
    4771: ('Kerberos pre-authentication failed', SOURCE_NONE),  # nopep8
    4772: ('A Kerberos authentication ticket request failed', SOURCE_NONE),  # nopep8
    4773: ('A Kerberos service ticket request failed', SOURCE_NONE),  # nopep8
    4774: ('An account was mapped for logon', SOURCE_NONE),  # nopep8
    4775: ('An account could not be mapped for logon', SOURCE_NONE),  # nopep8
    4776: ('The domain controller attempted to validate the credentials for an account', SOURCE_SEC),  # nopep8
    4777: ('The domain controller failed to validate the credentials for an account', SOURCE_SEC),  # nopep8
    4778: ('A session was reconnected to a Window Station', SOURCE_NONE),  # nopep8
    4779: ('A session was disconnected from a Window Station', SOURCE_NONE),  # nopep8
    4780: ('The ACL was set on accounts which are members of administrators groups', SOURCE_NONE),  # nopep8
    4781: ('The name of an account was changed', SOURCE_NONE),  # nopep8
    4782: ('The password hash an account was accessed', SOURCE_NONE),  # nopep8
    4783: ('A basic application group was created', SOURCE_NONE),  # nopep8
    4784: ('A basic application group was changed', SOURCE_NONE),  # nopep8
    4785: ('A member was added to a basic application group', SOURCE_NONE),  # nopep8
    4786: ('A member was removed from a basic application group', SOURCE_NONE),  # nopep8
    4787: ('A non-member was added to a basic application group', SOURCE_NONE),  # nopep8
    4788: ('A non-member was removed from a basic application group..', SOURCE_NONE),  # nopep8
    4789: ('A basic application group was deleted', SOURCE_NONE),  # nopep8
    4790: ('An LDAP query group was created', SOURCE_NONE),  # nopep8
    4791: ('A basic application group was changed', SOURCE_NONE),  # nopep8
    4792: ('An LDAP query group was deleted', SOURCE_NONE),  # nopep8
    4793: ('The Password Policy Checking API was called', SOURCE_NONE),  # nopep8
    4794: ('An attempt was made to set the Directory Services Restore Mode administrator password', SOURCE_NONE),  # nopep8
    4797: ('An attempt was made to query the existence of a blank password for an account', SOURCE_NONE),  # nopep8
    4798: ('A user\'s local group membership was enumerated.', SOURCE_NONE),  # nopep8
    4799: ('A security-enabled local group membership was enumerated', SOURCE_NONE),  # nopep8
    4800: ('The workstation was locked', SOURCE_NONE),  # nopep8
    4801: ('The workstation was unlocked', SOURCE_NONE),  # nopep8
    4802: ('The screen saver was invoked', SOURCE_NONE),  # nopep8
    4803: ('The screen saver was dismissed', SOURCE_NONE),  # nopep8
    4816: ('RPC detected an integrity violation while decrypting an incoming message', SOURCE_NONE),  # nopep8
    4817: ('Auditing settings on object were changed.', SOURCE_NONE),  # nopep8
    4818: ('Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy', SOURCE_NONE),  # nopep8
    4819: ('Central Access Policies on the machine have been changed', SOURCE_NONE),  # nopep8
    4820: ('A Kerberos Ticket-granting-ticket (TGT) was denied because the device does not meet the access control restrictions', SOURCE_NONE),  # nopep8
    4821: ('A Kerberos service ticket was denied because the user, device, or both does not meet the access control restrictions', SOURCE_NONE),  # nopep8
    4822: ('NTLM authentication failed because the account was a member of the Protected User group', SOURCE_NONE),  # nopep8
    4823: ('NTLM authentication failed because access control restrictions are required', SOURCE_NONE),  # nopep8
    4824: ('Kerberos preauthentication by using DES or RC4 failed because the account was a member of the Protected User group', SOURCE_NONE),  # nopep8
    4825: ('A user was denied the access to Remote Desktop. By default, users are allowed to connect only if they are members of the Remote Desktop Users group or Administrators group', SOURCE_NONE),  # nopep8
    4826: ('Boot Configuration Data loaded', SOURCE_NONE),  # nopep8
    4830: ('SID History was removed from an account', SOURCE_NONE),  # nopep8
    4864: ('A namespace collision was detected', SOURCE_NONE),  # nopep8
    4865: ('A trusted forest information entry was added', SOURCE_NONE),  # nopep8
    4866: ('A trusted forest information entry was removed', SOURCE_NONE),  # nopep8
    4867: ('A trusted forest information entry was modified', SOURCE_NONE),  # nopep8
    4868: ('The certificate manager denied a pending certificate request', SOURCE_NONE),  # nopep8
    4869: ('Certificate Services received a resubmitted certificate request', SOURCE_NONE),  # nopep8
    4870: ('Certificate Services revoked a certificate', SOURCE_NONE),  # nopep8
    4871: ('Certificate Services received a request to publish the certificate revocation list (CRL)', SOURCE_NONE),  # nopep8
    4872: ('Certificate Services published the certificate revocation list (CRL)', SOURCE_NONE),  # nopep8
    4873: ('A certificate request extension changed', SOURCE_NONE),  # nopep8
    4874: ('One or more certificate request attributes changed.', SOURCE_NONE),  # nopep8
    4875: ('Certificate Services received a request to shut down', SOURCE_NONE),  # nopep8
    4876: ('Certificate Services backup started', SOURCE_NONE),  # nopep8
    4877: ('Certificate Services backup completed', SOURCE_NONE),  # nopep8
    4878: ('Certificate Services restore started', SOURCE_NONE),  # nopep8
    4879: ('Certificate Services restore completed', SOURCE_NONE),  # nopep8
    4880: ('Certificate Services started', SOURCE_NONE),  # nopep8
    4881: ('Certificate Services stopped', SOURCE_NONE),  # nopep8
    4882: ('The security permissions for Certificate Services changed', SOURCE_NONE),  # nopep8
    4883: ('Certificate Services retrieved an archived key', SOURCE_NONE),  # nopep8
    4884: ('Certificate Services imported a certificate into its database', SOURCE_NONE),  # nopep8
    4885: ('The audit filter for Certificate Services changed', SOURCE_NONE),  # nopep8
    4886: ('Certificate Services received a certificate request', SOURCE_NONE),  # nopep8
    4887: ('Certificate Services approved a certificate request and issued a certificate', SOURCE_NONE),  # nopep8
    4888: ('Certificate Services denied a certificate request', SOURCE_NONE),  # nopep8
    4889: ('Certificate Services set the status of a certificate request to pending', SOURCE_NONE),  # nopep8
    4890: ('The certificate manager settings for Certificate Services changed.', SOURCE_NONE),  # nopep8
    4891: ('A configuration entry changed in Certificate Services', SOURCE_NONE),  # nopep8
    4892: ('A property of Certificate Services changed', SOURCE_NONE),  # nopep8
    4893: ('Certificate Services archived a key', SOURCE_NONE),  # nopep8
    4894: ('Certificate Services imported and archived a key', SOURCE_NONE),  # nopep8
    4895: ('Certificate Services published the CA certificate to Active Directory Domain Services', SOURCE_NONE),  # nopep8
    4896: ('One or more rows have been deleted from the certificate database', SOURCE_NONE),  # nopep8
    4897: ('Role separation enabled', SOURCE_NONE),  # nopep8
    4898: ('Certificate Services loaded a template', SOURCE_NONE),  # nopep8
    4899: ('A Certificate Services template was updated', SOURCE_NONE),  # nopep8
    4900: ('Certificate Services template security was updated', SOURCE_NONE),  # nopep8
    4902: ('The Per-user audit policy table was created', SOURCE_NONE),  # nopep8
    4904: ('An attempt was made to register a security event source', SOURCE_NONE),  # nopep8
    4905: ('An attempt was made to unregister a security event source', SOURCE_NONE),  # nopep8
    4906: ('The CrashOnAuditFail value has changed', SOURCE_NONE),  # nopep8
    4907: ('Auditing settings on object were changed', SOURCE_NONE),  # nopep8
    4908: ('Special Groups Logon table modified', SOURCE_NONE),  # nopep8
    4909: ('The local policy settings for the TBS were changed', SOURCE_NONE),  # nopep8
    4910: ('The group policy settings for the TBS were changed', SOURCE_NONE),  # nopep8
    4911: ('Resource attributes of the object were changed', SOURCE_NONE),  # nopep8
    4912: ('Per User Audit Policy was changed', SOURCE_NONE),  # nopep8
    4913: ('Central Access Policy on the object was changed', SOURCE_NONE),  # nopep8
    4928: ('An Active Directory replica source naming context was established', SOURCE_NONE),  # nopep8
    4929: ('An Active Directory replica source naming context was removed', SOURCE_NONE),  # nopep8
    4930: ('An Active Directory replica source naming context was modified', SOURCE_NONE),  # nopep8
    4931: ('An Active Directory replica destination naming context was modified', SOURCE_NONE),  # nopep8
    4932: ('Synchronization of a replica of an Active Directory naming context has begun', SOURCE_NONE),  # nopep8
    4933: ('Synchronization of a replica of an Active Directory naming context has ended', SOURCE_NONE),  # nopep8
    4934: ('Attributes of an Active Directory object were replicated', SOURCE_NONE),  # nopep8
    4935: ('Replication failure begins', SOURCE_NONE),  # nopep8
    4936: ('Replication failure ends', SOURCE_NONE),  # nopep8
    4937: ('A lingering object was removed from a replica', SOURCE_NONE),  # nopep8
    4944: ('The following policy was active when the Windows Firewall started', SOURCE_NONE),  # nopep8
    4945: ('A rule was listed when the Windows Firewall started', SOURCE_NONE),  # nopep8
    4946: ('A change has been made to Windows Firewall exception list. A rule was added', SOURCE_NONE),  # nopep8
    4947: ('A change has been made to Windows Firewall exception list. A rule was modified', SOURCE_NONE),  # nopep8
    4948: ('A change has been made to Windows Firewall exception list. A rule was deleted', SOURCE_NONE),  # nopep8
    4949: ('Windows Firewall settings were restored to the default values', SOURCE_NONE),  # nopep8
    4950: ('A Windows Firewall setting has changed', SOURCE_NONE),  # nopep8
    4951: ('A rule has been ignored because its major version number was not recognized by Windows Firewall', SOURCE_NONE),  # nopep8
    4952: ('Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall', SOURCE_NONE),  # nopep8
    4953: ('A rule has been ignored by Windows Firewall because it could not parse the rule', SOURCE_NONE),  # nopep8
    4954: ('Windows Firewall Group Policy settings has changed. The new settings have been applied', SOURCE_NONE),  # nopep8
    4956: ('Windows Firewall has changed the active profile', SOURCE_NONE),  # nopep8
    4957: ('Windows Firewall did not apply the following rule', SOURCE_NONE),  # nopep8
    4958: ('Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer', SOURCE_NONE),  # nopep8
    4960: ('IPsec dropped an inbound packet that failed an integrity check', SOURCE_NONE),  # nopep8
    4961: ('IPsec dropped an inbound packet that failed a replay check', SOURCE_NONE),  # nopep8
    4962: ('IPsec dropped an inbound packet that failed a replay check', SOURCE_NONE),  # nopep8
    4963: ('IPsec dropped an inbound clear text packet that should have been secured', SOURCE_NONE),  # nopep8
    4964: ('Special groups have been assigned to a new logon', SOURCE_NONE),  # nopep8
    4965: ('IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).', SOURCE_NONE),  # nopep8
    4976: ('During Main Mode negotiation, IPsec received an invalid negotiation packet.', SOURCE_NONE),  # nopep8
    4977: ('During Quick Mode negotiation, IPsec received an invalid negotiation packet.', SOURCE_NONE),  # nopep8
    4978: ('During Extended Mode negotiation, IPsec received an invalid negotiation packet.', SOURCE_NONE),  # nopep8
    4979: ('IPsec Main Mode and Extended Mode security associations were established.', SOURCE_NONE),  # nopep8
    4980: ('IPsec Main Mode and Extended Mode security associations were established', SOURCE_NONE),  # nopep8
    4981: ('IPsec Main Mode and Extended Mode security associations were established', SOURCE_NONE),  # nopep8
    4982: ('IPsec Main Mode and Extended Mode security associations were established', SOURCE_NONE),  # nopep8
    4983: ('An IPsec Extended Mode negotiation failed', SOURCE_NONE),  # nopep8
    4984: ('An IPsec Extended Mode negotiation failed', SOURCE_NONE),  # nopep8
    4985: ('The state of a transaction has changed', SOURCE_NONE),  # nopep8
    5024: ('The Windows Firewall Service has started successfully', SOURCE_NONE),  # nopep8
    5025: ('The Windows Firewall Service has been stopped', SOURCE_NONE),  # nopep8
    5027: ('The Windows Firewall Service was unable to retrieve the security policy from the local storage', SOURCE_NONE),  # nopep8
    5028: ('The Windows Firewall Service was unable to parse the new security policy.', SOURCE_NONE),  # nopep8
    5029: ('The Windows Firewall Service failed to initialize the driver', SOURCE_NONE),  # nopep8
    5030: ('The Windows Firewall Service failed to start', SOURCE_NONE),  # nopep8
    5031: ('The Windows Firewall Service blocked an application from accepting incoming connections on the network.', SOURCE_NONE),  # nopep8
    5032: ('Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network', SOURCE_NONE),  # nopep8
    5033: ('The Windows Firewall Driver has started successfully', SOURCE_NONE),  # nopep8
    5034: ('The Windows Firewall Driver has been stopped', SOURCE_NONE),  # nopep8
    5035: ('The Windows Firewall Driver failed to start', SOURCE_NONE),  # nopep8
    5037: ('The Windows Firewall Driver detected critical runtime error. Terminating', SOURCE_NONE),  # nopep8
    5038: ('Code integrity determined that the image hash of a file is not valid', SOURCE_NONE),  # nopep8
    5039: ('A registry key was virtualized.', SOURCE_NONE),  # nopep8
    5040: ('A change has been made to IPsec settings. An Authentication Set was added.', SOURCE_NONE),  # nopep8
    5041: ('A change has been made to IPsec settings. An Authentication Set was modified', SOURCE_NONE),  # nopep8
    5042: ('A change has been made to IPsec settings. An Authentication Set was deleted', SOURCE_NONE),  # nopep8
    5043: ('A change has been made to IPsec settings. A Connection Security Rule was added', SOURCE_NONE),  # nopep8
    5044: ('A change has been made to IPsec settings. A Connection Security Rule was modified', SOURCE_NONE),  # nopep8
    5045: ('A change has been made to IPsec settings. A Connection Security Rule was deleted', SOURCE_NONE),  # nopep8
    5046: ('A change has been made to IPsec settings. A Crypto Set was added', SOURCE_NONE),  # nopep8
    5047: ('A change has been made to IPsec settings. A Crypto Set was modified', SOURCE_NONE),  # nopep8
    5048: ('A change has been made to IPsec settings. A Crypto Set was deleted', SOURCE_NONE),  # nopep8
    5049: ('An IPsec Security Association was deleted', SOURCE_NONE),  # nopep8
    5050: ('An attempt to programmatically disable the Windows Firewall using a call to INetFwProfile.FirewallEnabled(FALSE', SOURCE_NONE),  # nopep8
    5051: ('A file was virtualized', SOURCE_NONE),  # nopep8
    5056: ('A cryptographic self test was performed', SOURCE_NONE),  # nopep8
    5057: ('A cryptographic primitive operation failed', SOURCE_NONE),  # nopep8
    5058: ('Key file operation', SOURCE_NONE),  # nopep8
    5059: ('Key migration operation', SOURCE_NONE),  # nopep8
    5060: ('Verification operation failed', SOURCE_NONE),  # nopep8
    5061: ('Cryptographic operation', SOURCE_NONE),  # nopep8
    5062: ('A kernel-mode cryptographic self test was performed', SOURCE_NONE),  # nopep8
    5063: ('A cryptographic provider operation was attempted', SOURCE_NONE),  # nopep8
    5064: ('A cryptographic context operation was attempted', SOURCE_NONE),  # nopep8
    5065: ('A cryptographic context modification was attempted', SOURCE_NONE),  # nopep8
    5066: ('A cryptographic function operation was attempted', SOURCE_NONE),  # nopep8
    5067: ('A cryptographic function modification was attempted', SOURCE_NONE),  # nopep8
    5068: ('A cryptographic function provider operation was attempted', SOURCE_NONE),  # nopep8
    5069: ('A cryptographic function property operation was attempted', SOURCE_NONE),  # nopep8
    5070: ('A cryptographic function property operation was attempted', SOURCE_NONE),  # nopep8
    5071: ('Key access denied by Microsoft key distribution service', SOURCE_NONE),  # nopep8
    5120: ('OCSP Responder Service Started', SOURCE_NONE),  # nopep8
    5121: ('OCSP Responder Service Stopped', SOURCE_NONE),  # nopep8
    5122: ('A Configuration entry changed in the OCSP Responder Service', SOURCE_NONE),  # nopep8
    5123: ('A configuration entry changed in the OCSP Responder Service', SOURCE_NONE),  # nopep8
    5124: ('A security setting was updated on OCSP Responder Service', SOURCE_NONE),  # nopep8
    5125: ('A request was submitted to OCSP Responder Service', SOURCE_NONE),  # nopep8
    5126: ('Signing Certificate was automatically updated by the OCSP Responder Service', SOURCE_NONE),  # nopep8
    5127: ('The OCSP Revocation Provider successfully updated the revocation information', SOURCE_NONE),  # nopep8
    5136: ('A directory service object was modified', SOURCE_NONE),  # nopep8
    5137: ('A directory service object was created', SOURCE_NONE),  # nopep8
    5138: ('A directory service object was undeleted', SOURCE_NONE),  # nopep8
    5139: ('A directory service object was moved', SOURCE_NONE),  # nopep8
    5140: ('A network share object was accessed', SOURCE_NONE),  # nopep8
    5141: ('A directory service object was deleted', SOURCE_NONE),  # nopep8
    5142: ('A network share object was added.', SOURCE_NONE),  # nopep8
    5143: ('A network share object was modified', SOURCE_NONE),  # nopep8
    5144: ('A network share object was deleted.', SOURCE_NONE),  # nopep8
    5145: ('A network share object was checked to see whether client can be granted desired access', SOURCE_NONE),  # nopep8
    5146: ('The Windows Filtering Platform has blocked a packet', SOURCE_NONE),  # nopep8
    5147: ('A more restrictive Windows Filtering Platform filter has blocked a packet', SOURCE_NONE),  # nopep8
    5148: ('The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.', SOURCE_NONE),  # nopep8
    5149: ('The DoS attack has subsided and normal processing is being resumed.', SOURCE_NONE),  # nopep8
    5150: ('The Windows Filtering Platform has blocked a packet.', SOURCE_NONE),  # nopep8
    5151: ('A more restrictive Windows Filtering Platform filter has blocked a packet.', SOURCE_NONE),  # nopep8
    5152: ('The Windows Filtering Platform blocked a packet', SOURCE_NONE),  # nopep8
    5153: ('A more restrictive Windows Filtering Platform filter has blocked a packet', SOURCE_NONE),  # nopep8
    5154: ('The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections', SOURCE_NONE),  # nopep8
    5155: ('The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections', SOURCE_NONE),  # nopep8
    5156: ('The Windows Filtering Platform has allowed a connection', SOURCE_NONE),  # nopep8
    5157: ('The Windows Filtering Platform has blocked a connection', SOURCE_NONE),  # nopep8
    5158: ('The Windows Filtering Platform has permitted a bind to a local port', SOURCE_NONE),  # nopep8
    5159: ('The Windows Filtering Platform has blocked a bind to a local port', SOURCE_NONE),  # nopep8
    5168: ('Spn check for SMB/SMB2 fails.', SOURCE_NONE),  # nopep8
    5169: ('A directory service object was modified', SOURCE_NONE),  # nopep8
    5170: ('A directory service object was modified during a background cleanup task', SOURCE_NONE),  # nopep8
    5376: ('Credential Manager credentials were backed up', SOURCE_NONE),  # nopep8
    5377: ('Credential Manager credentials were restored from a backup', SOURCE_NONE),  # nopep8
    5378: ('The requested credentials delegation was disallowed by policy', SOURCE_NONE),  # nopep8
    5379: ('Credential Manager credentials were read', SOURCE_NONE),  # nopep8
    5380: ('Vault Find Credential', SOURCE_NONE),  # nopep8
    5381: ('Vault credentials were read', SOURCE_NONE),  # nopep8
    5382: ('Vault credentials were read', SOURCE_NONE),  # nopep8
    5440: ('The following callout was present when the Windows Filtering Platform Base Filtering Engine started', SOURCE_NONE),  # nopep8
    5441: ('The following filter was present when the Windows Filtering Platform Base Filtering Engine started', SOURCE_NONE),  # nopep8
    5442: ('The following provider was present when the Windows Filtering Platform Base Filtering Engine started', SOURCE_NONE),  # nopep8
    5443: ('The following provider context was present when the Windows Filtering Platform Base Filtering Engine started', SOURCE_NONE),  # nopep8
    5444: ('The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started', SOURCE_NONE),  # nopep8
    5446: ('A Windows Filtering Platform callout has been changed', SOURCE_NONE),  # nopep8
    5447: ('A Windows Filtering Platform filter has been changed', SOURCE_NONE),  # nopep8
    5448: ('A Windows Filtering Platform provider has been changed', SOURCE_NONE),  # nopep8
    5449: ('A Windows Filtering Platform provider context has been changed', SOURCE_NONE),  # nopep8
    5450: ('A Windows Filtering Platform sub-layer has been changed', SOURCE_NONE),  # nopep8
    5451: ('An IPsec Quick Mode security association was established', SOURCE_NONE),  # nopep8
    5452: ('An IPsec Quick Mode security association ended', SOURCE_NONE),  # nopep8
    5453: ('An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started', SOURCE_NONE),  # nopep8
    5456: ('PAStore Engine applied Active Directory storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5457: ('PAStore Engine failed to apply Active Directory storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5458: ('PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5459: ('PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5460: ('PAStore Engine applied local registry storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5461: ('PAStore Engine failed to apply local registry storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5462: ('PAStore Engine failed to apply some rules of the active IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5463: ('PAStore Engine polled for changes to the active IPsec policy and detected no changes', SOURCE_NONE),  # nopep8
    5464: ('PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services', SOURCE_NONE),  # nopep8
    5465: ('PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully', SOURCE_NONE),  # nopep8
    5466: ('PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead', SOURCE_NONE),  # nopep8   # nopep8
    5467: ('PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy', SOURCE_NONE),  # nopep8
    5468: ('PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes', SOURCE_NONE),  # nopep8
    5471: ('PAStore Engine loaded local storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5472: ('PAStore Engine failed to load local storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5473: ('PAStore Engine loaded directory storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5474: ('PAStore Engine failed to load directory storage IPsec policy on the computer', SOURCE_NONE),  # nopep8
    5477: ('PAStore Engine failed to add quick mode filter', SOURCE_NONE),  # nopep8
    5478: ('IPsec Services has started successfully', SOURCE_NONE),  # nopep8
    5479: ('IPsec Services has been shut down successfully', SOURCE_NONE),  # nopep8
    5480: ('IPsec Services failed to get the complete list of network interfaces on the computer', SOURCE_NONE),  # nopep8
    5483: ('IPsec Services failed to initialize RPC server. IPsec Services could not be started', SOURCE_NONE),  # nopep8
    5484: ('IPsec Services has experienced a critical failure and has been shut down', SOURCE_NONE),  # nopep8
    5485: ('IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces', SOURCE_NONE),  # nopep8
    5632: ('A request was made to authenticate to a wireless network', SOURCE_NONE),  # nopep8
    5633: ('A request was made to authenticate to a wired network', SOURCE_NONE),  # nopep8
    5712: ('A Remote Procedure Call (RPC) was attempted', SOURCE_NONE),  # nopep8
    5888: ('An object in the COM+ Catalog was modified', SOURCE_NONE),  # nopep8
    5889: ('An object was deleted from the COM+ Catalog', SOURCE_NONE),  # nopep8
    5890: ('An object was added to the COM+ Catalog', SOURCE_NONE),  # nopep8
    6144: ('Security policy in the group policy objects has been applied successfully', SOURCE_NONE),  # nopep8
    6145: ('One or more errors occured while processing security policy in the group policy objects', SOURCE_NONE),  # nopep8
    6272: ('Network Policy Server granted access to a user', SOURCE_NONE),  # nopep8
    6273: ('Network Policy Server denied access to a user', SOURCE_NONE),  # nopep8
    6274: ('Network Policy Server discarded the request for a user', SOURCE_NONE),  # nopep8
    6275: ('Network Policy Server discarded the accounting request for a user', SOURCE_NONE),  # nopep8
    6276: ('Network Policy Server quarantined a user', SOURCE_NONE),  # nopep8
    6277: ('Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy', SOURCE_NONE),  # nopep8
    6278: ('Network Policy Server granted full access to a user because the host met the defined health policy', SOURCE_NONE),  # nopep8
    6279: ('Network Policy Server locked the user account due to repeated failed authentication attempts', SOURCE_NONE),  # nopep8
    6280: ('Network Policy Server unlocked the user account', SOURCE_NONE),  # nopep8
    6281: ('Code Integrity determined that the page hashes of an image file are not valid...', SOURCE_NONE),  # nopep8
    6400: ('BranchCache: Received an incorrectly formatted response while discovering availability of content.', SOURCE_NONE),  # nopep8
    6401: ('BranchCache: Received invalid data from a peer. Data discarded.', SOURCE_NONE),  # nopep8
    6402: ('BranchCache: The message to the hosted cache offering it data is incorrectly formatted.', SOURCE_NONE),  # nopep8
    6403: ('BranchCache: The hosted cache sent an incorrectly formatted response to the client\'s message to offer it data.', SOURCE_NONE),  # nopep8
    6404: ('BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.', SOURCE_NONE),  # nopep8
    6408: ('Registered product failed and Windows Firewall is now controlling the filtering for...', SOURCE_NONE),  # nopep8
    6409: ('BranchCache: A service connection point object could not be parsed', SOURCE_NONE),  # nopep8
    6410: ('Code integrity determined that a file does not meet the security requirements to load into a process. This could be due to the use of shared sections or other issues', SOURCE_NONE),  # nopep8
    6416: ('A new external device was recognized by the system.', SOURCE_NONE),  # nopep8
    6417: ('The FIPS mode crypto selftests succeeded', SOURCE_NONE),  # nopep8
    6418: ('The FIPS mode crypto selftests failed', SOURCE_NONE),  # nopep8
    6419: ('A request was made to disable a device', SOURCE_NONE),  # nopep8
    6420: ('A device was disabled', SOURCE_NONE),  # nopep8
    6421: ('A request was made to enable a device', SOURCE_NONE),  # nopep8
    6422: ('A device was enabled', SOURCE_NONE),  # nopep8
    6423: ('The installation of this device is forbidden by system policy', SOURCE_NONE),  # nopep8
    6424: ('The installation of this device was allowed, after having previously been forbidden by policy', SOURCE_NONE),  # nopep8
    8191: ('Highest System-Defined Audit Message Value', SOURCE_NONE),  # nopep8
}

SQL = {
    24000: ('SQL audit event', SOURCE_NONE),  # nopep8
    24001: ('Login succeeded (action_id LGIS)', SOURCE_NONE),  # nopep8
    24002: ('Logout succeeded (action_id LGO)', SOURCE_NONE),  # nopep8
    24003: ('Login failed (action_id LGIF)', SOURCE_NONE),  # nopep8
    24004: ('Change own password succeeded (action_id PWCS; class_type LX)', SOURCE_NONE),  # nopep8
    24005: ('Change own password failed (action_id PWCS; class_type LX)', SOURCE_NONE),  # nopep8
    24006: ('Change password succeeded (action_id PWC class_type LX)', SOURCE_NONE),  # nopep8
    24007: ('Change password failed (action_id PWC class_type LX)', SOURCE_NONE),  # nopep8
    24008: ('Reset own password succeeded (action_id PWRS; class_type LX)', SOURCE_NONE),  # nopep8
    24009: ('Reset own password failed (action_id PWRS; class_type LX)', SOURCE_NONE),  # nopep8
    24010: ('Reset password succeeded (action_id PWR; class_type LX)', SOURCE_NONE),  # nopep8
    24011: ('Reset password failed (action_id PWR; class_type LX)', SOURCE_NONE),  # nopep8
    24012: ('Must change password (action_id PWMC)', SOURCE_NONE),  # nopep8
    24013: ('Account unlocked (action_id PWU)', SOURCE_NONE),  # nopep8
    24014: ('Change application role password succeeded (action_id PWC; class_type AR)', SOURCE_NONE),  # nopep8
    24015: ('Change application role password failed (action_id PWC class_type AR)', SOURCE_NONE),  # nopep8
    24016: ('Add member to server role succeeded (action_id APRL class_type SG)', SOURCE_NONE),  # nopep8
    24017: ('Add member to server role failed (action_id APRL class_type SG)', SOURCE_NONE),  # nopep8
    24018: ('Remove member from server role succeeded (action_id DPRL class_type SG)', SOURCE_NONE),  # nopep8
    24019: ('Remove member from server role failed (action_id DPRL class_type SG)', SOURCE_NONE),  # nopep8
    24020: ('Add member to database role succeeded (action_id APRL class_type RL)', SOURCE_NONE),  # nopep8
    24021: ('Add member to database role failed (action_id APRL class_type RL)', SOURCE_NONE),  # nopep8
    24022: ('Remove member from database role succeeded (action_id DPRL class_type RL)', SOURCE_NONE),  # nopep8
    24023: ('Remove member from database role failed (action_id DPRL class_type RL)', SOURCE_NONE),  # nopep8
    24024: ('Issued database backup command (action_id BA class_type DB)', SOURCE_NONE),  # nopep8
    24025: ('Issued transaction log backup command (action_id BAL)', SOURCE_NONE),  # nopep8
    24026: ('Issued database restore command (action_id RS class_type DB)', SOURCE_NONE),  # nopep8
    24027: ('Issued transaction log restore command (action_id RS class_type DB)', SOURCE_NONE),  # nopep8
    24028: ('Issued database console command (action_id DBCC)', SOURCE_NONE),  # nopep8
    24029: ('Issued a bulk administration command (action_id ADBO)', SOURCE_NONE),  # nopep8
    24030: ('Issued an alter connection command (action_id ALCN)', SOURCE_NONE),  # nopep8
    24031: ('Issued an alter resources command (action_id ALRS)', SOURCE_NONE),  # nopep8
    24032: ('Issued an alter server state command (action_id ALSS)', SOURCE_NONE),  # nopep8
    24033: ('Issued an alter server settings command (action_id ALST)', SOURCE_NONE),  # nopep8
    24034: ('Issued a view server state command (action_id VSST)', SOURCE_NONE),  # nopep8
    24035: ('Issued an external access assembly command (action_id XA)', SOURCE_NONE),  # nopep8
    24036: ('Issued an unsafe assembly command (action_id XU)', SOURCE_NONE),  # nopep8
    24037: ('Issued an alter resource governor command (action_id ALRS class_type RG)', SOURCE_NONE),  # nopep8
    24038: ('Issued a database authenticate command (action_id AUTH)', SOURCE_NONE),  # nopep8
    24039: ('Issued a database checkpoint command (action_id CP)', SOURCE_NONE),  # nopep8
    24040: ('Issued a database show plan command (action_id SPLN)', SOURCE_NONE),  # nopep8
    24041: ('Issued a subscribe to query information command (action_id SUQN)', SOURCE_NONE),  # nopep8
    24042: ('Issued a view database state command (action_id VDST)', SOURCE_NONE),  # nopep8
    24043: ('Issued a change server audit command (action_id AL class_type A)', SOURCE_NONE),  # nopep8
    24044: ('Issued a change server audit specification command (action_id AL class_type SA)', SOURCE_NONE),  # nopep8
    24045: ('Issued a change database audit specification command (action_id AL class_type DA)', SOURCE_NONE),  # nopep8
    24046: ('Issued a create server audit command (action_id CR class_type A)', SOURCE_NONE),  # nopep8
    24047: ('Issued a create server audit specification command (action_id CR class_type SA)', SOURCE_NONE),  # nopep8
    24048: ('Issued a create database audit specification command (action_id CR class_type DA)', SOURCE_NONE),  # nopep8
    24049: ('Issued a delete server audit command (action_id DR class_type A)', SOURCE_NONE),  # nopep8
    24050: ('Issued a delete server audit specification command (action_id DR class_type SA)', SOURCE_NONE),  # nopep8
    24051: ('Issued a delete database audit specification command (action_id DR class_type DA)', SOURCE_NONE),  # nopep8
    24052: ('Audit failure (action_id AUSF)', SOURCE_NONE),  # nopep8
    24053: ('Audit session changed (action_id AUSC)', SOURCE_NONE),  # nopep8
    24054: ('Started SQL server (action_id SVSR)', SOURCE_NONE),  # nopep8
    24055: ('Paused SQL server (action_id SVPD)', SOURCE_NONE),  # nopep8
    24056: ('Resumed SQL server (action_id SVCN)', SOURCE_NONE),  # nopep8
    24057: ('Stopped SQL server (action_id SVSD)', SOURCE_NONE),  # nopep8
    24058: ('Issued a create server object command (action_id CR; class_type AG, EP, SD, SE, T)', SOURCE_NONE),  # nopep8
    24059: ('Issued a change server object command (action_id AL; class_type AG, EP, SD, SE, T)', SOURCE_NONE),  # nopep8
    24060: ('Issued a delete server object command (action_id DR; class_type AG, EP, SD, SE, T)', SOURCE_NONE),  # nopep8
    24061: ('Issued a create server setting command (action_id CR class_type SR)', SOURCE_NONE),  # nopep8
    24062: ('Issued a change server setting command (action_id AL class_type SR)', SOURCE_NONE),  # nopep8
    24063: ('Issued a delete server setting command (action_id DR class_type SR)', SOURCE_NONE),  # nopep8
    24064: ('Issued a create server cryptographic provider command (action_id CR class_type CP)', SOURCE_NONE),  # nopep8
    24065: ('Issued a delete server cryptographic provider command (action_id DR class_type CP)', SOURCE_NONE),  # nopep8
    24066: ('Issued a change server cryptographic provider command (action_id AL class_type CP)', SOURCE_NONE),  # nopep8
    24067: ('Issued a create server credential command (action_id CR class_type CD)', SOURCE_NONE),  # nopep8
    24068: ('Issued a delete server credential command (action_id DR class_type CD)', SOURCE_NONE),  # nopep8
    24069: ('Issued a change server credential command (action_id AL class_type CD)', SOURCE_NONE),  # nopep8
    24070: ('Issued a change server master key command (action_id AL class_type MK)', SOURCE_NONE),  # nopep8
    24071: ('Issued a back up server master key command (action_id BA class_type MK)', SOURCE_NONE),  # nopep8
    24072: ('Issued a restore server master key command (action_id RS class_type MK)', SOURCE_NONE),  # nopep8
    24073: ('Issued a map server credential to login command (action_id CMLG)', SOURCE_NONE),  # nopep8
    24074: ('Issued a remove map between server credential and login command (action_id NMLG)', SOURCE_NONE),  # nopep8
    24075: ('Issued a create server principal command (action_id CR class_type LX, SL)', SOURCE_NONE),  # nopep8
    24076: ('Issued a delete server principal command (action_id DR class_type LX, SL)', SOURCE_NONE),  # nopep8
    24077: ('Issued a change server principal credentials command (action_id CCLG)', SOURCE_NONE),  # nopep8
    24078: ('Issued a disable server principal command (action_id LGDA)', SOURCE_NONE),  # nopep8
    24079: ('Issued a change server principal default database command (action_id LGDB)', SOURCE_NONE),  # nopep8
    24080: ('Issued an enable server principal command (action_id LGEA)', SOURCE_NONE),  # nopep8
    24081: ('Issued a change server principal default language command (action_id LGLG)', SOURCE_NONE),  # nopep8
    24082: ('Issued a change server principal password expiration command (action_id PWEX)', SOURCE_NONE),  # nopep8
    24083: ('Issued a change server principal password policy command (action_id PWPL)', SOURCE_NONE),  # nopep8
    24084: ('Issued a change server principal name command (action_id LGNM)', SOURCE_NONE),  # nopep8
    24085: ('Issued a create database command (action_id CR class_type DB)', SOURCE_NONE),  # nopep8
    24086: ('Issued a change database command (action_id AL class_type DB)', SOURCE_NONE),  # nopep8
    24087: ('Issued a delete database command (action_id DR class_type DB)', SOURCE_NONE),  # nopep8
    24088: ('Issued a create certificate command (action_id CR class_type CR)', SOURCE_NONE),  # nopep8
    24089: ('Issued a change certificate command (action_id AL class_type CR)', SOURCE_NONE),  # nopep8
    24090: ('Issued a delete certificate command (action_id DR class_type CR)', SOURCE_NONE),  # nopep8
    24091: ('Issued a back up certificate command (action_id BA class_type CR)', SOURCE_NONE),  # nopep8
    24092: ('Issued an access certificate command (action_id AS class_type CR)', SOURCE_NONE),  # nopep8
    24093: ('Issued a create asymmetric key command (action_id CR class_type AK)', SOURCE_NONE),  # nopep8
    24094: ('Issued a change asymmetric key command (action_id AL class_type AK)', SOURCE_NONE),  # nopep8
    24095: ('Issued a delete asymmetric key command (action_id DR class_type AK)', SOURCE_NONE),  # nopep8
    24096: ('Issued an access asymmetric key command (action_id AS class_type AK)', SOURCE_NONE),  # nopep8
    24097: ('Issued a create database master key command (action_id CR class_type MK)', SOURCE_NONE),  # nopep8
    24098: ('Issued a change database master key command (action_id AL class_type MK)', SOURCE_NONE),  # nopep8
    24099: ('Issued a delete database master key command (action_id DR class_type MK)', SOURCE_NONE),  # nopep8
    24100: ('Issued a back up database master key command (action_id BA class_type MK)', SOURCE_NONE),  # nopep8
    24101: ('Issued a restore database master key command (action_id RS class_type MK)', SOURCE_NONE),  # nopep8
    24102: ('Issued an open database master key command (action_id OP class_type MK)', SOURCE_NONE),  # nopep8
    24103: ('Issued a create database symmetric key command (action_id CR class_type SK)', SOURCE_NONE),  # nopep8
    24104: ('Issued a change database symmetric key command (action_id AL class_type SK)', SOURCE_NONE),  # nopep8
    24105: ('Issued a delete database symmetric key command (action_id DR class_type SK)', SOURCE_NONE),  # nopep8
    24106: ('Issued a back up database symmetric key command (action_id BA class_type SK)', SOURCE_NONE),  # nopep8
    24107: ('Issued an open database symmetric key command (action_id OP class_type SK)', SOURCE_NONE),  # nopep8
    24108: ('Issued a create database object command (action_id CR)', SOURCE_NONE),  # nopep8
    24109: ('Issued a change database object command (action_id AL)', SOURCE_NONE),  # nopep8
    24110: ('Issued a delete database object command (action_id DR)', SOURCE_NONE),  # nopep8
    24111: ('Issued an access database object command (action_id AS)', SOURCE_NONE),  # nopep8
    24112: ('Issued a create assembly command (action_id CR class_type AS)', SOURCE_NONE),  # nopep8
    24113: ('Issued a change assembly command (action_id AL class_type AS)', SOURCE_NONE),  # nopep8
    24114: ('Issued a delete assembly command (action_id DR class_type AS)', SOURCE_NONE),  # nopep8
    24115: ('Issued a create schema command (action_id CR class_type SC)', SOURCE_NONE),  # nopep8
    24116: ('Issued a change schema command (action_id AL class_type SC)', SOURCE_NONE),  # nopep8
    24117: ('Issued a delete schema command (action_id DR class_type SC)', SOURCE_NONE),  # nopep8
    24118: ('Issued a create database encryption key command (action_id CR class_type DK)', SOURCE_NONE),  # nopep8
    24119: ('Issued a change database encryption key command (action_id AL class_type DK)', SOURCE_NONE),  # nopep8
    24120: ('Issued a delete database encryption key command (action_id DR class_type DK)', SOURCE_NONE),  # nopep8
    24121: ('Issued a create database user command (action_id CR; class_type US)', SOURCE_NONE),  # nopep8
    24122: ('Issued a change database user command (action_id AL; class_type US)', SOURCE_NONE),  # nopep8
    24123: ('Issued a delete database user command (action_id DR; class_type US)', SOURCE_NONE),  # nopep8
    24124: ('Issued a create database role command (action_id CR class_type RL)', SOURCE_NONE),  # nopep8
    24125: ('Issued a change database role command (action_id AL class_type RL)', SOURCE_NONE),  # nopep8
    24126: ('Issued a delete database role command (action_id DR class_type RL)', SOURCE_NONE),  # nopep8
    24127: ('Issued a create application role command (action_id CR class_type AR)', SOURCE_NONE),  # nopep8
    24128: ('Issued a change application role command (action_id AL class_type AR)', SOURCE_NONE),  # nopep8
    24129: ('Issued a delete application role command (action_id DR class_type AR)', SOURCE_NONE),  # nopep8
    24130: ('Issued a change database user login command (action_id USAF)', SOURCE_NONE),  # nopep8
    24131: ('Issued an auto-change database user login command (action_id USLG)', SOURCE_NONE),  # nopep8
    24132: ('Issued a create schema object command (action_id CR class_type D)', SOURCE_NONE),  # nopep8
    24133: ('Issued a change schema object command (action_id AL class_type D)', SOURCE_NONE),  # nopep8
    24134: ('Issued a delete schema object command (action_id DR class_type D)', SOURCE_NONE),  # nopep8
    24135: ('Issued a transfer schema object command (action_id TRO class_type D)', SOURCE_NONE),  # nopep8
    24136: ('Issued a create schema type command (action_id CR class_type TY)', SOURCE_NONE),  # nopep8
    24137: ('Issued a change schema type command (action_id AL class_type TY)', SOURCE_NONE),  # nopep8
    24138: ('Issued a delete schema type command (action_id DR class_type TY)', SOURCE_NONE),  # nopep8
    24139: ('Issued a transfer schema type command (action_id TRO class_type TY)', SOURCE_NONE),  # nopep8
    24140: ('Issued a create XML schema collection command (action_id CR class_type SX)', SOURCE_NONE),  # nopep8
    24141: ('Issued a change XML schema collection command (action_id AL class_type SX)', SOURCE_NONE),  # nopep8
    24142: ('Issued a delete XML schema collection command (action_id DR class_type SX)', SOURCE_NONE),  # nopep8
    24143: ('Issued a transfer XML schema collection command (action_id TRO class_type SX)', SOURCE_NONE),  # nopep8
    24144: ('Issued an impersonate within server scope command (action_id IMP; class_type LX)', SOURCE_NONE),  # nopep8
    24145: ('Issued an impersonate within database scope command (action_id IMP; class_type US)', SOURCE_NONE),  # nopep8
    24146: ('Issued a change server object owner command (action_id TO class_type SG)', SOURCE_NONE),  # nopep8
    24147: ('Issued a change database owner command (action_id TO class_type DB)', SOURCE_NONE),  # nopep8
    24148: ('Issued a change schema owner command (action_id TO class_type SC)', SOURCE_NONE),  # nopep8
    24150: ('Issued a change role owner command (action_id TO class_type RL)', SOURCE_NONE),  # nopep8
    24151: ('Issued a change database object owner command (action_id TO)', SOURCE_NONE),  # nopep8
    24152: ('Issued a change symmetric key owner command (action_id TO class_type SK)', SOURCE_NONE),  # nopep8
    24153: ('Issued a change certificate owner command (action_id TO class_type CR)', SOURCE_NONE),  # nopep8
    24154: ('Issued a change asymmetric key owner command (action_id TO class_type AK)', SOURCE_NONE),  # nopep8
    24155: ('Issued a change schema object owner command (action_id TO class_type OB)', SOURCE_NONE),  # nopep8
    24156: ('Issued a change schema type owner command (action_id TO class_type TY)', SOURCE_NONE),  # nopep8
    24157: ('Issued a change XML schema collection owner command (action_id TO class_type SX)', SOURCE_NONE),  # nopep8
    24158: ('Grant server permissions succeeded (action_id G class_type SR)', SOURCE_NONE),  # nopep8
    24159: ('Grant server permissions failed (action_id G class_type SR)', SOURCE_NONE),  # nopep8
    24160: ('Grant server permissions with grant succeeded (action_id GWG class_type SR)', SOURCE_NONE),  # nopep8
    24161: ('Grant server permissions with grant failed (action_id GWG class_type SR)', SOURCE_NONE),  # nopep8
    24162: ('Deny server permissions succeeded (action_id D class_type SR)', SOURCE_NONE),  # nopep8
    24163: ('Deny server permissions failed (action_id D class_type SR)', SOURCE_NONE),  # nopep8
    24164: ('Deny server permissions with cascade succeeded (action_id DWC class_type SR)', SOURCE_NONE),  # nopep8
    24165: ('Deny server permissions with cascade failed (action_id DWC class_type SR)', SOURCE_NONE),  # nopep8
    24166: ('Revoke server permissions succeeded (action_id R class_type SR)', SOURCE_NONE),  # nopep8
    24167: ('Revoke server permissions failed (action_id R class_type SR)', SOURCE_NONE),  # nopep8
    24168: ('Revoke server permissions with grant succeeded (action_id RWG class_type SR)', SOURCE_NONE),  # nopep8
    24169: ('Revoke server permissions with grant failed (action_id RWG class_type SR)', SOURCE_NONE),  # nopep8
    24170: ('Revoke server permissions with cascade succeeded (action_id RWC class_type SR)', SOURCE_NONE),  # nopep8
    24171: ('Revoke server permissions with cascade failed (action_id RWC class_type SR)', SOURCE_NONE),  # nopep8
    24172: ('Issued grant server object permissions command (action_id G; class_type LX)', SOURCE_NONE),  # nopep8
    24173: ('Issued grant server object permissions with grant command (action_id GWG; class_type LX)', SOURCE_NONE),  # nopep8
    24174: ('Issued deny server object permissions command (action_id D; class_type LX)', SOURCE_NONE),  # nopep8
    24175: ('Issued deny server object permissions with cascade command (action_id DWC; class_type LX)', SOURCE_NONE),  # nopep8
    24176: ('Issued revoke server object permissions command (action_id R; class_type LX)', SOURCE_NONE),  # nopep8
    24177: ('Issued revoke server object permissions with grant command (action_id; RWG class_type LX)', SOURCE_NONE),  # nopep8
    24178: ('Issued revoke server object permissions with cascade command (action_id RWC; class_type LX)', SOURCE_NONE),  # nopep8
    24179: ('Grant database permissions succeeded (action_id G class_type DB)', SOURCE_NONE),  # nopep8
    24180: ('Grant database permissions failed (action_id G class_type DB)', SOURCE_NONE),  # nopep8
    24181: ('Grant database permissions with grant succeeded (action_id GWG class_type DB)', SOURCE_NONE),  # nopep8
    24182: ('Grant database permissions with grant failed (action_id GWG class_type DB)', SOURCE_NONE),  # nopep8
    24183: ('Deny database permissions succeeded (action_id D class_type DB)', SOURCE_NONE),  # nopep8
    24184: ('Deny database permissions failed (action_id D class_type DB)', SOURCE_NONE),  # nopep8
    24185: ('Deny database permissions with cascade succeeded (action_id DWC class_type DB)', SOURCE_NONE),  # nopep8
    24186: ('Deny database permissions with cascade failed (action_id DWC class_type DB)', SOURCE_NONE),  # nopep8
    24187: ('Revoke database permissions succeeded (action_id R class_type DB)', SOURCE_NONE),  # nopep8
    24188: ('Revoke database permissions failed (action_id R class_type DB)', SOURCE_NONE),  # nopep8
    24189: ('Revoke database permissions with grant succeeded (action_id RWG class_type DB)', SOURCE_NONE),  # nopep8
    24190: ('Revoke database permissions with grant failed (action_id RWG class_type DB)', SOURCE_NONE),  # nopep8
    24191: ('Revoke database permissions with cascade succeeded (action_id RWC class_type DB)', SOURCE_NONE),  # nopep8
    24192: ('Revoke database permissions with cascade failed (action_id RWC class_type DB)', SOURCE_NONE),  # nopep8
    24193: ('Issued grant database object permissions command (action_id G class_type US)', SOURCE_NONE),  # nopep8
    24194: ('Issued grant database object permissions with grant command (action_id GWG; class_type US)', SOURCE_NONE),  # nopep8
    24195: ('Issued deny database object permissions command (action_id D; class_type US)', SOURCE_NONE),  # nopep8
    24196: ('Issued deny database object permissions with cascade command (action_id DWC; class_type US)', SOURCE_NONE),  # nopep8
    24197: ('Issued revoke database object permissions command (action_id R; class_type US)', SOURCE_NONE),  # nopep8
    24198: ('Issued revoke database object permissions with grant command (action_id RWG; class_type US)', SOURCE_NONE),  # nopep8
    24199: ('Issued revoke database object permissions with cascade command (action_id RWC; class_type US)', SOURCE_NONE),  # nopep8
    24200: ('Issued grant schema permissions command (action_id G class_type SC)', SOURCE_NONE),  # nopep8
    24201: ('Issued grant schema permissions with grant command (action_id GWG class_type SC)', SOURCE_NONE),  # nopep8
    24202: ('Issued deny schema permissions command (action_id D class_type SC)', SOURCE_NONE),  # nopep8
    24203: ('Issued deny schema permissions with cascade command (action_id DWC class_type SC)', SOURCE_NONE),  # nopep8
    24204: ('Issued revoke schema permissions command (action_id R class_type SC)', SOURCE_NONE),  # nopep8
    24205: ('Issued revoke schema permissions with grant command (action_id RWG class_type SC)', SOURCE_NONE),  # nopep8
    24206: ('Issued revoke schema permissions with cascade command (action_id RWC class_type SC)', SOURCE_NONE),  # nopep8
    24207: ('Issued grant assembly permissions command (action_id G class_type AS)', SOURCE_NONE),  # nopep8
    24208: ('Issued grant assembly permissions with grant command (action_id GWG class_type AS)', SOURCE_NONE),  # nopep8
    24209: ('Issued deny assembly permissions command (action_id D class_type AS)', SOURCE_NONE),  # nopep8
    24210: ('Issued deny assembly permissions with cascade command (action_id DWC class_type AS)', SOURCE_NONE),  # nopep8
    24211: ('Issued revoke assembly permissions command (action_id R class_type AS)', SOURCE_NONE),  # nopep8
    24212: ('Issued revoke assembly permissions with grant command (action_id RWG class_type AS)', SOURCE_NONE),  # nopep8
    24213: ('Issued revoke assembly permissions with cascade command (action_id RWC class_type AS)', SOURCE_NONE),  # nopep8
    24214: ('Issued grant database role permissions command (action_id G class_type RL)', SOURCE_NONE),  # nopep8
    24215: ('Issued grant database role permissions with grant command (action_id GWG class_type RL)', SOURCE_NONE),  # nopep8
    24216: ('Issued deny database role permissions command (action_id D class_type RL)', SOURCE_NONE),  # nopep8
    24217: ('Issued deny database role permissions with cascade command (action_id DWC class_type RL)', SOURCE_NONE),  # nopep8
    24218: ('Issued revoke database role permissions command (action_id R class_type RL)', SOURCE_NONE),  # nopep8
    24219: ('Issued revoke database role permissions with grant command (action_id RWG class_type RL)', SOURCE_NONE),  # nopep8
    24220: ('Issued revoke database role permissions with cascade command (action_id RWC class_type RL)', SOURCE_NONE),  # nopep8
    24221: ('Issued grant application role permissions command (action_id G class_type AR)', SOURCE_NONE),  # nopep8
    24222: ('Issued grant application role permissions with grant command (action_id GWG class_type AR)', SOURCE_NONE),  # nopep8
    24223: ('Issued deny application role permissions command (action_id D class_type AR)', SOURCE_NONE),  # nopep8
    24224: ('Issued deny application role permissions with cascade command (action_id DWC class_type AR)', SOURCE_NONE),  # nopep8
    24225: ('Issued revoke application role permissions command (action_id R class_type AR)', SOURCE_NONE),  # nopep8
    24226: ('Issued revoke application role permissions with grant command (action_id RWG class_type AR)', SOURCE_NONE),  # nopep8
    24227: ('Issued revoke application role permissions with cascade command (action_id RWC class_type AR)', SOURCE_NONE),  # nopep8
    24228: ('Issued grant symmetric key permissions command (action_id G class_type SK)', SOURCE_NONE),  # nopep8
    24229: ('Issued grant symmetric key permissions with grant command (action_id GWG class_type SK)', SOURCE_NONE),  # nopep8
    24230: ('Issued deny symmetric key permissions command (action_id D class_type SK)', SOURCE_NONE),  # nopep8
    24231: ('Issued deny symmetric key permissions with cascade command (action_id DWC class_type SK)', SOURCE_NONE),  # nopep8
    24232: ('Issued revoke symmetric key permissions command (action_id R class_type SK)', SOURCE_NONE),  # nopep8
    24233: ('Issued revoke symmetric key permissions with grant command (action_id RWG class_type SK)', SOURCE_NONE),  # nopep8
    24234: ('Issued revoke symmetric key permissions with cascade command (action_id RWC class_type SK)', SOURCE_NONE),  # nopep8
    24235: ('Issued grant certificate permissions command (action_id G class_type CR)', SOURCE_NONE),  # nopep8
    24236: ('Issued grant certificate permissions with grant command (action_id GWG class_type CR)', SOURCE_NONE),  # nopep8
    24237: ('Issued deny certificate permissions command (action_id D class_type CR)', SOURCE_NONE),  # nopep8
    24238: ('Issued deny certificate permissions with cascade command (action_id DWC class_type CR)', SOURCE_NONE),  # nopep8
    24239: ('Issued revoke certificate permissions command (action_id R class_type CR)', SOURCE_NONE),  # nopep8
    24240: ('Issued revoke certificate permissions with grant command (action_id RWG class_type CR)', SOURCE_NONE),  # nopep8
    24241: ('Issued revoke certificate permissions with cascade command (action_id RWC class_type CR)', SOURCE_NONE),  # nopep8
    24242: ('Issued grant asymmetric key permissions command (action_id G class_type AK)', SOURCE_NONE),  # nopep8
    24243: ('Issued grant asymmetric key permissions with grant command (action_id GWG class_type AK)', SOURCE_NONE),  # nopep8
    24244: ('Issued deny asymmetric key permissions command (action_id D class_type AK)', SOURCE_NONE),  # nopep8
    24245: ('Issued deny asymmetric key permissions with cascade command (action_id DWC class_type AK)', SOURCE_NONE),  # nopep8
    24246: ('Issued revoke asymmetric key permissions command (action_id R class_type AK)', SOURCE_NONE),  # nopep8
    24247: ('Issued revoke asymmetric key permissions with grant command (action_id RWG class_type AK)', SOURCE_NONE),  # nopep8
    24248: ('Issued revoke asymmetric key permissions with cascade command (action_id RWC class_type AK)', SOURCE_NONE),  # nopep8
    24249: ('Issued grant schema object permissions command (action_id G class_type OB)', SOURCE_NONE),  # nopep8
    24250: ('Issued grant schema object permissions with grant command (action_id GWG class_type OB)', SOURCE_NONE),  # nopep8
    24251: ('Issued deny schema object permissions command (action_id D class_type OB)', SOURCE_NONE),  # nopep8
    24252: ('Issued deny schema object permissions with cascade command (action_id DWC class_type OB)', SOURCE_NONE),  # nopep8
    24253: ('Issued revoke schema object permissions command (action_id R class_type OB)', SOURCE_NONE),  # nopep8
    24254: ('Issued revoke schema object permissions with grant command (action_id RWG class_type OB)', SOURCE_NONE),  # nopep8
    24255: ('Issued revoke schema object permissions with cascade command (action_id RWC class_type OB)', SOURCE_NONE),  # nopep8
    24256: ('Issued grant schema type permissions command (action_id G class_type TY)', SOURCE_NONE),  # nopep8
    24257: ('Issued grant schema type permissions with grant command (action_id GWG class_type TY)', SOURCE_NONE),  # nopep8
    24258: ('Issued deny schema type permissions command (action_id D class_type TY)', SOURCE_NONE),  # nopep8
    24259: ('Issued deny schema type permissions with cascade command (action_id DWC class_type TY)', SOURCE_NONE),  # nopep8
    24260: ('Issued revoke schema type permissions command (action_id R class_type TY)', SOURCE_NONE),  # nopep8
    24261: ('Issued revoke schema type permissions with grant command (action_id RWG class_type TY)', SOURCE_NONE),  # nopep8
    24262: ('Issued revoke schema type permissions with cascade command (action_id RWC class_type TY)', SOURCE_NONE),  # nopep8
    24263: ('Issued grant XML schema collection permissions command (action_id G class_type SX)', SOURCE_NONE),  # nopep8
    24264: ('Issued grant XML schema collection permissions with grant command (action_id GWG class_type SX)', SOURCE_NONE),  # nopep8
    24265: ('Issued deny XML schema collection permissions command (action_id D class_type SX)', SOURCE_NONE),  # nopep8
    24266: ('Issued deny XML schema collection permissions with cascade command (action_id DWC class_type SX)', SOURCE_NONE),  # nopep8
    24267: ('Issued revoke XML schema collection permissions command (action_id R class_type SX)', SOURCE_NONE),  # nopep8
    24268: ('Issued revoke XML schema collection permissions with grant command (action_id RWG class_type SX)', SOURCE_NONE),  # nopep8
    24269: ('Issued revoke XML schema collection permissions with cascade command (action_id RWC class_type SX)', SOURCE_NONE),  # nopep8
    24270: ('Issued reference database object permissions command (action_id RF)', SOURCE_NONE),  # nopep8
    24271: ('Issued send service request command (action_id SN)', SOURCE_NONE),  # nopep8
    24272: ('Issued check permissions with schema command (action_id VWCT)', SOURCE_NONE),  # nopep8
    24273: ('Issued use service broker transport security command (action_id LGB)', SOURCE_NONE),  # nopep8
    24274: ('Issued use database mirroring transport security command (action_id LGM)', SOURCE_NONE),  # nopep8
    24275: ('Issued alter trace command (action_id ALTR)', SOURCE_NONE),  # nopep8
    24276: ('Issued start trace command (action_id TASA)', SOURCE_NONE),  # nopep8
    24277: ('Issued stop trace command (action_id TASP)', SOURCE_NONE),  # nopep8
    24278: ('Issued enable trace C2 audit mode command (action_id C2ON)', SOURCE_NONE),  # nopep8
    24279: ('Issued disable trace C2 audit mode command (action_id C2OF)', SOURCE_NONE),  # nopep8
    24280: ('Issued server full-text command (action_id FT)', SOURCE_NONE),  # nopep8
    24281: ('Issued select command (action_id SL)', SOURCE_NONE),  # nopep8
    24282: ('Issued update command (action_id UP)', SOURCE_NONE),  # nopep8
    24283: ('Issued insert command (action_id IN)', SOURCE_NONE),  # nopep8
    24284: ('Issued delete command (action_id DL)', SOURCE_NONE),  # nopep8
    24285: ('Issued execute command (action_id EX)', SOURCE_NONE),  # nopep8
    24286: ('Issued receive command (action_id RC)', SOURCE_NONE),  # nopep8
    24287: ('Issued check references command (action_id RF)', SOURCE_NONE),  # nopep8
    24288: ('Issued a create user-defined server role command (action_id CR class_type SG)', SOURCE_NONE),  # nopep8
    24289: ('Issued a change user-defined server role command (action_id AL class_type SG)', SOURCE_NONE),  # nopep8
    24290: ('Issued a delete user-defined server role command (action_id DR class_type SG)', SOURCE_NONE),  # nopep8
    24291: ('Issued grant user-defined server role permissions command (action_id G class_type SG)', SOURCE_NONE),  # nopep8
    24292: ('Issued grant user-defined server role permissions with grant command (action_id GWG class_type SG)', SOURCE_NONE),  # nopep8
    24293: ('Issued deny user-defined server role permissions command (action_id D class_type SG)', SOURCE_NONE),  # nopep8
    24294: ('Issued deny user-defined server role permissions with cascade command (action_id DWC class_type SG)', SOURCE_NONE),  # nopep8
    24295: ('Issued revoke user-defined server role permissions command (action_id R class_type SG)', SOURCE_NONE),  # nopep8
    24296: ('Issued revoke user-defined server role permissions with grant command (action_id RWG class_type SG)', SOURCE_NONE),  # nopep8
    24297: ('Issued revoke user-defined server role permissions with cascade command (action_id RWC class_type SG)', SOURCE_NONE),  # nopep8
    24298: ('Database login succeeded (action_id DBAS)', SOURCE_NONE),  # nopep8
    24299: ('Database login failed (action_id DBAF)', SOURCE_NONE),  # nopep8
    24300: ('Database logout successful (action_id DAGL)', SOURCE_NONE),  # nopep8
    24301: ('Change password succeeded (action_id PWC; class_type US)', SOURCE_NONE),  # nopep8
    24302: ('Change password failed (action_id PWC; class_type US)', SOURCE_NONE),  # nopep8
    24303: ('Change own password succeeded (action_id PWCS; class_type US)', SOURCE_NONE),  # nopep8
    24304: ('Change own password failed (action_id PWCS; class_type US)', SOURCE_NONE),  # nopep8
    24305: ('Reset own password succeeded (action_id PWRS; class_type US)', SOURCE_NONE),  # nopep8
    24306: ('Reset own password failed (action_id PWRS; class_type US)', SOURCE_NONE),  # nopep8
    24307: ('Reset password succeeded (action_id PWR; class_type US)', SOURCE_NONE),  # nopep8
    24308: ('Reset password failed (action_id PWR; class_type US)', SOURCE_NONE),  # nopep8
    24309: ('Copy password (action_id USTC)', SOURCE_NONE),  # nopep8
    24310: ('User-defined SQL audit event (action_id UDAU)', SOURCE_NONE),  # nopep8
    24311: ('Issued a change database audit command (action_id AL class_type DU)', SOURCE_NONE),  # nopep8
    24312: ('Issued a create database audit command (action_id CR class_type DU)', SOURCE_NONE),  # nopep8
    24313: ('Issued a delete database audit command (action_id DR class_type DU)', SOURCE_NONE),  # nopep8
    24314: ('Issued a begin transaction command (action_id TXBG)', SOURCE_NONE),  # nopep8
    24315: ('Issued a commit transaction command (action_id TXCM)', SOURCE_NONE),  # nopep8
    24316: ('Issued a rollback transaction command (action_id TXRB)', SOURCE_NONE),  # nopep8
    24317: ('Issued a create column master key command (action_id CR; class_type CM)', SOURCE_NONE),  # nopep8
    24318: ('Issued a delete column master key command (action_id DR; class_type CM)', SOURCE_NONE),  # nopep8
    24319: ('A column master key was viewed (action_id VW; class_type CM)', SOURCE_NONE),  # nopep8
    24320: ('Issued a create column encryption key command (action_id CR; class_type CK)', SOURCE_NONE),  # nopep8
    24321: ('Issued a change column encryption key command (action_id AL; class_type CK)', SOURCE_NONE),  # nopep8
    24322: ('Issued a delete column encryption key command (action_id DR; class_type CK)', SOURCE_NONE),  # nopep8
    24323: ('A column encryption key was viewed (action_id VW; class_type CK)', SOURCE_NONE),  # nopep8
    24324: ('Issued a create database credential command (action_id CR; class_type DC)', SOURCE_NONE),  # nopep8
    24325: ('Issued a change database credential command (action_id AL; class_type DC)', SOURCE_NONE),  # nopep8
    24326: ('Issued a delete database credential command (action_id DR; class_type DC)', SOURCE_NONE),  # nopep8
    24327: ('Issued a change database scoped configuration command (action_id AL; class_type DS)', SOURCE_NONE),  # nopep8
    24328: ('Issued a create external data source command (action_id CR; class_type ED)', SOURCE_NONE),  # nopep8
    24329: ('Issued a change external data source command (action_id AL; class_type ED)', SOURCE_NONE),  # nopep8
    24330: ('Issued a delete external data source command (action_id DR; class_type ED)', SOURCE_NONE),  # nopep8
    24331: ('Issued a create external file format command (action_id CR; class_type EF)', SOURCE_NONE),  # nopep8
    24332: ('Issued a delete external file format command (action_id DR; class_type EF)', SOURCE_NONE),  # nopep8
    24333: ('Issued a create external resource pool command (action_id CR; class_type ER)', SOURCE_NONE),  # nopep8
    24334: ('Issued a change external resource pool command (action_id AL; class_type ER)', SOURCE_NONE),  # nopep8
    24335: ('Issued a delete external resource pool command (action_id DR; class_type ER)', SOURCE_NONE),  # nopep8
    24337: ('Global transaction login (action_id LGG)', SOURCE_NONE),  # nopep8
    24338: ('Grant permissions on a database scoped credential succeeded (action_id G; class_type DC)', SOURCE_NONE),  # nopep8
    24339: ('Grant permissions on a database scoped credential failed (action_id G; class_type DC)', SOURCE_NONE),  # nopep8
    24340: ('Grant permissions on a database scoped credential with grant succeeded (action_id GWG; class_type DC)', SOURCE_NONE),  # nopep8
    24341: ('Grant permissions on a database scoped credential with grant failed (action_id GWG; class_type DC)', SOURCE_NONE),  # nopep8
    24342: ('Deny permissions on a database scoped credential succeeded (action_id D; class_type DC)', SOURCE_NONE),  # nopep8
    24343: ('Deny permissions on a database scoped credential failed (action_id D; class_type DC)', SOURCE_NONE),  # nopep8
    24344: ('Deny permissions on a database scoped credential with cascade succeeded (action_id DWC; class_type DC)', SOURCE_NONE),  # nopep8
    24345: ('Deny permissions on a database scoped credential with cascade failed (action_id DWC; class_type DC)', SOURCE_NONE),  # nopep8
    24346: ('Revoke permissions on a database scoped credential succeeded (action_id R; class_type DC)', SOURCE_NONE),  # nopep8
    24347: ('Revoke permissions on a database scoped credential failed (action_id R; class_type DC)', SOURCE_NONE),  # nopep8
    24348: ('Revoke permissions with cascade on a database scoped credential succeeded (action_id RWC; class_type DC)', SOURCE_NONE),  # nopep8
    24349: ('Issued a change assembly owner command (action_id TO class_type AS)', SOURCE_NONE),  # nopep8
    24350: ('Revoke permissions with cascade on a database scoped credential failed (action_id RWC; class_type DC)', SOURCE_NONE),  # nopep8
    24351: ('Revoke permissions with grant on a database scoped credential succeeded (action_id RWG; class_type DC)', SOURCE_NONE),  # nopep8
    24352: ('Revoke permissions with grant on a database scoped credential failed (action_id RWG; class_type DC)', SOURCE_NONE),  # nopep8
    24353: ('Issued a change database scoped credential owner command (action_id TO; class_type DC)', SOURCE_NONE),  # nopep8
    24354: ('Issued a create external library command (action_id CR; class_type EL)', SOURCE_NONE),  # nopep8
    24355: ('Issued a change external library command (action_id AL; class_type EL)', SOURCE_NONE),  # nopep8
    24356: ('Issued a drop external library command (action_id DR; class_type EL)', SOURCE_NONE),  # nopep8
    24357: ('Grant permissions on an external library succeeded (action_id G; class_type EL)', SOURCE_NONE),  # nopep8
    24358: ('Grant permissions on an external library failed (action_id G; class_type EL)', SOURCE_NONE),  # nopep8
    24359: ('Grant permissions on an external library with grant succeeded (action_id GWG; class_type EL)', SOURCE_NONE),  # nopep8
    24360: ('Grant permissions on an external library with grant failed (action_id GWG; class_type EL)', SOURCE_NONE),  # nopep8
    24361: ('Deny permissions on an external library succeeded (action_id D; class_type EL)', SOURCE_NONE),  # nopep8
    24362: ('Deny permissions on an external library failed (action_id D; class_type EL)', SOURCE_NONE),  # nopep8
    24363: ('Deny permissions on an external library with cascade succeeded (action_id DWC; class_type EL)', SOURCE_NONE),  # nopep8
    24364: ('Deny permissions on an external library with cascade failed (action_id DWC; class_type EL)', SOURCE_NONE),  # nopep8
    24365: ('Revoke permissions on an external library succeeded (action_id R; class_type EL)', SOURCE_NONE),  # nopep8
    24366: ('Revoke permissions on an external library failed (action_id R; class_type EL)', SOURCE_NONE),  # nopep8
    24367: ('Revoke permissions with cascade on an external library succeeded (action_id RWC; class_type EL)', SOURCE_NONE),  # nopep8
    24368: ('Revoke permissions with cascade on an external library failed (action_id RWC; class_type EL)', SOURCE_NONE),  # nopep8
    24369: ('Revoke permissions with grant on an external library succeeded (action_id RWG; class_type EL)', SOURCE_NONE),  # nopep8
    24370: ('Revoke permissions with grant on an external library failed (action_id RWG; class_type EL)', SOURCE_NONE),  # nopep8
    24371: ('Issued a create database scoped resource governor command (action_id CR; class_type DR)', SOURCE_NONE),  # nopep8
    24372: ('Issued a change database scoped resource governor command (action_id AL; class_type DR)', SOURCE_NONE),  # nopep8
    24373: ('Issued a drop database scoped resource governor command (action_id DR; class_type DR)', SOURCE_NONE),  # nopep8
    24374: ('Issued a database bulk administration command (action_id DABO; class_type DB)', SOURCE_NONE),  # nopep8
    24375: ('Command to change permission failed (action_id D, DWC, G, GWG, R, RWC, RWG; class_type DC, EL)', SOURCE_NONE),  # nopep8
}

EXCHANGE = {
    25000: ('Undocumented Exchange mailbox operation', SOURCE_NONE),  # nopep8
    25001: ('Operation Copy - Copy item to another Exchange mailbox folder', SOURCE_NONE),  # nopep8
    25002: ('Operation Create - Create item in Exchange mailbox', SOURCE_NONE),  # nopep8
    25003: ('Operation FolderBind - Access Exchange mailbox folder', SOURCE_NONE),  # nopep8
    25004: ('Operation HardDelete - Delete Exchange mailbox item permanently from Recoverable Items folder', SOURCE_NONE),  # nopep8
    25005: ('Operation MessageBind - Access Exchange mailbox item', SOURCE_NONE),  # nopep8
    25006: ('Operation Move - Move item to another Exchange mailbox folder', SOURCE_NONE),  # nopep8
    25007: ('Operation MoveToDeletedItems - Move Exchange mailbox item to Deleted Items folder', SOURCE_NONE),  # nopep8
    25008: ('Operation SendAs - Send message using Send As Exchange mailbox permissions', SOURCE_NONE),  # nopep8
    25009: ('Operation SendOnBehalf - Send message using Send on Behalf Exchange mailbox permissions', SOURCE_NONE),  # nopep8
    25010: ('Operation SoftDelete - Delete Exchange mailbox item from Deleted Items folder', SOURCE_NONE),  # nopep8
    25011: ('Operation Update - Update Exchange mailbox item\'s properties', SOURCE_NONE),  # nopep8
    25100: ('Information Event - Mailbox audit policy applied', SOURCE_NONE),  # nopep8
    25100: ('Undocumented Exchange admin operation', SOURCE_NONE),  # nopep8
    25101: ('Add-ADPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25102: ('Add-AvailabilityAddressSpace Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25103: ('Add-ContentFilterPhrase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25104: ('Add-DatabaseAvailabilityGroupServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25105: ('Add-DistributionGroupMember Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25106: ('Add-FederatedDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25107: ('Add-IPAllowListEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25108: ('Add-IPAllowListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25109: ('Add-IPBlockListEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25110: ('Add-IPBlockListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25111: ('Add-MailboxDatabaseCopy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25112: ('Add-MailboxFolderPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25113: ('Add-MailboxPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25114: ('Add-ManagementRoleEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25115: ('Add-PublicFolderAdministrativePermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25116: ('Add-PublicFolderClientPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25117: ('Add-RoleGroupMember Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25118: ('Clean-MailboxDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25119: ('Clear-ActiveSyncDevice Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25120: ('Clear-TextMessagingAccount Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25121: ('Compare-TextMessagingVerificationCode Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25122: ('Connect-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25123: ('Disable-AddressListPaging Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25124: ('Disable-CmdletExtensionAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25125: ('Disable-DistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25126: ('Disable-InboxRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25127: ('Disable-JournalRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25128: ('Disable-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25129: ('Disable-MailContact Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25130: ('Disable-MailPublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25131: ('Disable-MailUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25132: ('Disable-OutlookAnywhere Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25133: ('Disable-OutlookProtectionRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25134: ('Disable-RemoteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25135: ('Disable-ServiceEmailChannel Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25136: ('Disable-TransportAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25137: ('Disable-TransportRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25138: ('Disable-UMAutoAttendant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25139: ('Disable-UMIPGateway Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25140: ('Disable-UMMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25141: ('Disable-UMServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25142: ('Dismount-Database Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25143: ('Enable-AddressListPaging Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25144: ('Enable-AntispamUpdates Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25145: ('Enable-CmdletExtensionAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25146: ('Enable-DistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25147: ('Enable-ExchangeCertificate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25148: ('Enable-InboxRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25149: ('Enable-JournalRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25150: ('Enable-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25151: ('Enable-MailContact Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25152: ('Enable-MailPublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25153: ('Enable-MailUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25154: ('Enable-OutlookAnywhere Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25155: ('Enable-OutlookProtectionRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25156: ('Enable-RemoteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25157: ('Enable-ServiceEmailChannel Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25158: ('Enable-TransportAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25159: ('Enable-TransportRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25160: ('Enable-UMAutoAttendant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25161: ('Enable-UMIPGateway Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25162: ('Enable-UMMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25163: ('Enable-UMServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25164: ('Export-ActiveSyncLog Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25165: ('Export-AutoDiscoverConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25166: ('Export-ExchangeCertificate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25167: ('Export-JournalRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25168: ('Export-MailboxDiagnosticLogs Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25169: ('Export-Message Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25170: ('Export-RecipientDataProperty Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25171: ('Export-TransportRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25172: ('Export-UMCallDataRecord Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25173: ('Export-UMPrompt Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25174: ('Import-ExchangeCertificate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25175: ('Import-JournalRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25176: ('Import-RecipientDataProperty Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25177: ('Import-TransportRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25178: ('Import-UMPrompt Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25179: ('Install-TransportAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25180: ('Mount-Database Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25181: ('Move-ActiveMailboxDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25182: ('Move-AddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25183: ('Move-DatabasePath Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25184: ('Move-OfflineAddressBook Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25185: ('New-AcceptedDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25186: ('New-ActiveSyncDeviceAccessRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25187: ('New-ActiveSyncMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25188: ('New-ActiveSyncVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25189: ('New-AddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25190: ('New-AdminAuditLogSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25191: ('New-AutodiscoverVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25192: ('New-AvailabilityReportOutage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25193: ('New-ClientAccessArray Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25194: ('New-DatabaseAvailabilityGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25195: ('New-DatabaseAvailabilityGroupNetwork Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25196: ('New-DeliveryAgentConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25197: ('New-DistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25198: ('New-DynamicDistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25199: ('New-EcpVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25200: ('New-EdgeSubscription Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25201: ('New-EdgeSyncServiceConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25202: ('New-EmailAddressPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25203: ('New-ExchangeCertificate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25204: ('New-FederationTrust Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25205: ('New-ForeignConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25206: ('New-GlobalAddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25207: ('New-InboxRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25208: ('New-JournalRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25209: ('New-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25210: ('New-MailboxAuditLogSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25211: ('New-MailboxDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25212: ('New-MailboxFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25213: ('New-MailboxRepairRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25214: ('New-MailboxRestoreRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25215: ('New-MailContact Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25216: ('New-MailMessage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25217: ('New-MailUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25218: ('New-ManagedContentSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25219: ('New-ManagedFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25220: ('New-ManagedFolderMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25221: ('New-ManagementRole Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25222: ('New-ManagementRoleAssignment Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25223: ('New-ManagementScope Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25224: ('New-MessageClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25225: ('New-MoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25226: ('New-OabVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25227: ('New-OfflineAddressBook Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25228: ('New-OrganizationRelationship Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25229: ('New-OutlookProtectionRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25230: ('New-OutlookProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25231: ('New-OwaMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25232: ('New-OwaVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25233: ('New-PublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25234: ('New-PublicFolderDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25235: ('New-PublicFolderDatabaseRepairRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25236: ('New-ReceiveConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25237: ('New-RemoteDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25238: ('New-RemoteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25239: ('New-RetentionPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25240: ('New-RetentionPolicyTag Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25241: ('New-RoleAssignmentPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25242: ('New-RoleGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25243: ('New-RoutingGroupConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25244: ('New-RpcClientAccess Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25245: ('New-SendConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25246: ('New-SharingPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25247: ('New-SystemMessage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25248: ('New-ThrottlingPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25249: ('New-TransportRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25250: ('New-UMAutoAttendant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25251: ('New-UMDialPlan Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25252: ('New-UMHuntGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25253: ('New-UMIPGateway Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25254: ('New-UMMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25255: ('New-WebServicesVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25256: ('New-X400AuthoritativeDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25257: ('Remove-AcceptedDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25258: ('Remove-ActiveSyncDevice Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25259: ('Remove-ActiveSyncDeviceAccessRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25260: ('Remove-ActiveSyncDeviceClass Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25261: ('Remove-ActiveSyncMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25262: ('Remove-ActiveSyncVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25263: ('Remove-AddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25264: ('Remove-ADPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25265: ('Remove-AutodiscoverVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25266: ('Remove-AvailabilityAddressSpace Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25267: ('Remove-AvailabilityReportOutage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25268: ('Remove-ClientAccessArray Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25269: ('Remove-ContentFilterPhrase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25270: ('Remove-DatabaseAvailabilityGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25271: ('Remove-DatabaseAvailabilityGroupNetwork Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25272: ('Remove-DatabaseAvailabilityGroupServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25273: ('Remove-DeliveryAgentConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25274: ('Remove-DistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25275: ('Remove-DistributionGroupMember Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25276: ('Remove-DynamicDistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25277: ('Remove-EcpVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25278: ('Remove-EdgeSubscription Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25279: ('Remove-EmailAddressPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25280: ('Remove-ExchangeCertificate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25281: ('Remove-FederatedDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25282: ('Remove-FederationTrust Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25283: ('Remove-ForeignConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25284: ('Remove-GlobalAddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25285: ('Remove-InboxRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25286: ('Remove-IPAllowListEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25287: ('Remove-IPAllowListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25288: ('Remove-IPBlockListEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25289: ('Remove-IPBlockListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25290: ('Remove-JournalRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25291: ('Remove-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25292: ('Remove-MailboxDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25293: ('Remove-MailboxDatabaseCopy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25294: ('Remove-MailboxFolderPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25295: ('Remove-MailboxPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25296: ('Remove-MailboxRestoreRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25297: ('Remove-MailContact Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25298: ('Remove-MailUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25299: ('Remove-ManagedContentSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25300: ('Remove-ManagedFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25301: ('Remove-ManagedFolderMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25302: ('Remove-ManagementRole Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25303: ('Remove-ManagementRoleAssignment Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25304: ('Remove-ManagementRoleEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25305: ('Remove-ManagementScope Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25306: ('Remove-Message Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25307: ('Remove-MessageClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25308: ('Remove-MoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25309: ('Remove-OabVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25310: ('Remove-OfflineAddressBook Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25311: ('Remove-OrganizationRelationship Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25312: ('Remove-OutlookProtectionRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25313: ('Remove-OutlookProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25314: ('Remove-OwaMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25315: ('Remove-OwaVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25316: ('Remove-PublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25317: ('Remove-PublicFolderAdministrativePermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25318: ('Remove-PublicFolderClientPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25319: ('Remove-PublicFolderDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25320: ('Remove-ReceiveConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25321: ('Remove-RemoteDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25322: ('Remove-RemoteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25323: ('Remove-RetentionPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25324: ('Remove-RetentionPolicyTag Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25325: ('Remove-RoleAssignmentPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25326: ('Remove-RoleGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25327: ('Remove-RoleGroupMember Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25328: ('Remove-RoutingGroupConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25329: ('Remove-RpcClientAccess Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25330: ('Remove-SendConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25331: ('Remove-SharingPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25332: ('Remove-StoreMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25333: ('Remove-SystemMessage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25334: ('Remove-ThrottlingPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25335: ('Remove-TransportRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25336: ('Remove-UMAutoAttendant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25337: ('Remove-UMDialPlan Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25338: ('Remove-UMHuntGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25339: ('Remove-UMIPGateway Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25340: ('Remove-UMMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25341: ('Remove-WebServicesVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25342: ('Remove-X400AuthoritativeDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25343: ('Restore-DatabaseAvailabilityGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25344: ('Restore-DetailsTemplate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25345: ('Restore-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25346: ('Resume-MailboxDatabaseCopy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25347: ('Resume-MailboxExportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25348: ('Resume-MailboxRestoreRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25349: ('Resume-Message Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25350: ('Resume-MoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25351: ('Resume-PublicFolderReplication Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25352: ('Resume-Queue Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25353: ('Retry-Queue Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25354: ('Send-TextMessagingVerificationCode Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25355: ('Set-AcceptedDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25356: ('Set-ActiveSyncDeviceAccessRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25357: ('Set-ActiveSyncMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25358: ('Set-ActiveSyncOrganizationSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25359: ('Set-ActiveSyncVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25360: ('Set-AddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25361: ('Set-AdminAuditLogConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25362: ('Set-ADServerSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25363: ('Set-ADSite Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25364: ('Set-AdSiteLink Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25365: ('Set-AutodiscoverVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25366: ('Set-AvailabilityConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25367: ('Set-AvailabilityReportOutage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25368: ('Set-CalendarNotification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25369: ('Set-CalendarProcessing Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25370: ('Set-CASMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25371: ('Set-ClientAccessArray Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25372: ('Set-ClientAccessServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25373: ('Set-CmdletExtensionAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25374: ('Set-Contact Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25375: ('Set-ContentFilterConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25376: ('Set-DatabaseAvailabilityGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25377: ('Set-DatabaseAvailabilityGroupNetwork Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25378: ('Set-DeliveryAgentConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25379: ('Set-DetailsTemplate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25380: ('Set-DistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25381: ('Set-DynamicDistributionGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25382: ('Set-EcpVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25383: ('Set-EdgeSyncServiceConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25384: ('Set-EmailAddressPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25385: ('Set-EventLogLevel Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25386: ('Set-ExchangeAssistanceConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25387: ('Set-ExchangeServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25388: ('Set-FederatedOrganizationIdentifier Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25389: ('Set-FederationTrust Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25390: ('Set-ForeignConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25391: ('Set-GlobalAddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25392: ('Set-Group Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25393: ('Set-ImapSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25394: ('Set-InboxRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25395: ('Set-IPAllowListConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25396: ('Set-IPAllowListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25397: ('Set-IPAllowListProvidersConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25398: ('Set-IPBlockListConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25399: ('Set-IPBlockListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25400: ('Set-IPBlockListProvidersConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25401: ('Set-IRMConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25402: ('Set-JournalRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25403: ('Set-Mailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25404: ('Set-MailboxAuditBypassAssociation Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25405: ('Set-MailboxAutoReplyConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25406: ('Set-MailboxCalendarConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25407: ('Set-MailboxCalendarFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25408: ('Set-MailboxDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25409: ('Set-MailboxDatabaseCopy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25410: ('Set-MailboxFolderPermission Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25411: ('Set-MailboxJunkEmailConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25412: ('Set-MailboxMessageConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25413: ('Set-MailboxRegionalConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25414: ('Set-MailboxRestoreRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25415: ('Set-MailboxServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25416: ('Set-MailboxSpellingConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25417: ('Set-MailContact Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25418: ('Set-MailPublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25419: ('Set-MailUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25420: ('Set-ManagedContentSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25421: ('Set-ManagedFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25422: ('Set-ManagedFolderMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25423: ('Set-ManagementRoleAssignment Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25424: ('Set-ManagementRoleEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25425: ('Set-ManagementScope Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25426: ('Set-MessageClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25427: ('Set-MoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25428: ('Set-OabVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25429: ('Set-OfflineAddressBook Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25430: ('Set-OrganizationConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25431: ('Set-OrganizationRelationship Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25432: ('Set-OutlookAnywhere Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25433: ('Set-OutlookProtectionRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25434: ('Set-OutlookProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25435: ('Set-OwaMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25436: ('Set-OwaVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25437: ('Set-PopSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25438: ('Set-PowerShellVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25439: ('Set-PublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25440: ('Set-PublicFolderDatabase Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25441: ('Set-ReceiveConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25442: ('Set-RecipientFilterConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25443: ('Set-RemoteDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25444: ('Set-RemoteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25445: ('Set-ResourceConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25446: ('Set-RetentionPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25447: ('Set-RetentionPolicyTag Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25448: ('Set-RoleAssignmentPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25449: ('Set-RoleGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25450: ('Set-RoutingGroupConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25451: ('Set-RpcClientAccess Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25452: ('Set-SendConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25453: ('Set-SenderFilterConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25454: ('Set-SenderIdConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25455: ('Set-SenderReputationConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25456: ('Set-SharingPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25457: ('Set-SystemMessage Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25458: ('Set-TextMessagingAccount Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25459: ('Set-ThrottlingPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25460: ('Set-ThrottlingPolicyAssociation Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25461: ('Set-TransportAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25462: ('Set-TransportConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25463: ('Set-TransportRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25464: ('Set-TransportServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25465: ('Set-UMAutoAttendant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25466: ('Set-UMDialPlan Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25467: ('Set-UMIPGateway Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25468: ('Set-UMMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25469: ('Set-UMMailboxPIN Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25470: ('Set-UMMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25471: ('Set-UmServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25472: ('Set-User Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25473: ('Set-WebServicesVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25474: ('Set-X400AuthoritativeDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25475: ('Start-DatabaseAvailabilityGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25476: ('Start-EdgeSynchronization Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25477: ('Start-ManagedFolderAssistant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25478: ('Start-RetentionAutoTagLearning Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25479: ('Stop-DatabaseAvailabilityGroup Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25480: ('Stop-ManagedFolderAssistant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25481: ('Suspend-MailboxDatabaseCopy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25482: ('Suspend-MailboxRestoreRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25483: ('Suspend-Message Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25484: ('Suspend-MoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25485: ('Suspend-PublicFolderReplication Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25486: ('Suspend-Queue Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25487: ('Test-ActiveSyncConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25488: ('Test-AssistantHealth Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25489: ('Test-CalendarConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25490: ('Test-EcpConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25491: ('Test-EdgeSynchronization Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25492: ('Test-ExchangeSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25493: ('Test-FederationTrust Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25494: ('Test-FederationTrustCertificate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25495: ('Test-ImapConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25496: ('Test-IPAllowListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25497: ('Test-IPBlockListProvider Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25498: ('Test-IRMConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25499: ('Test-Mailflow Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25500: ('Test-MAPIConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25501: ('Test-MRSHealth Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25502: ('Test-OrganizationRelationship Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25503: ('Test-OutlookConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25504: ('Test-OutlookWebServices Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25505: ('Test-OwaConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25506: ('Test-PopConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25507: ('Test-PowerShellConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25508: ('Test-ReplicationHealth Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25509: ('Test-SenderId Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25510: ('Test-ServiceHealth Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25511: ('Test-SmtpConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25512: ('Test-SystemHealth Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25513: ('Test-UMConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25514: ('Test-WebServicesConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25515: ('Uninstall-TransportAgent Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25516: ('Update-AddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25517: ('Update-DistributionGroupMember Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25518: ('Update-EmailAddressPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25519: ('Update-FileDistributionService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25520: ('Update-GlobalAddressList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25521: ('Update-MailboxDatabaseCopy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25522: ('Update-OfflineAddressBook Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25523: ('Update-PublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25524: ('Update-PublicFolderHierarchy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25525: ('Update-Recipient Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25526: ('Update-RoleGroupMember Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25527: ('Update-SafeList Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25528: ('Write-AdminAuditLog Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25529: ('Add-GlobalMonitoringOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25530: ('Add-ResubmitRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25531: ('Add-ServerMonitoringOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25532: ('Clear-MobileDevice Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25533: ('Complete-MigrationBatch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25534: ('Disable-App Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25535: ('Disable-MailboxQuarantine Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25536: ('Disable-UMCallAnsweringRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25537: ('Disable-UMService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25538: ('Dump-ProvisioningCache Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25539: ('Enable-App Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25540: ('Enable-MailboxQuarantine Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25541: ('Enable-UMCallAnsweringRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25542: ('Enable-UMService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25543: ('Export-DlpPolicyCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25544: ('Export-MigrationReport Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25545: ('Import-DlpPolicyCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25546: ('Import-DlpPolicyTemplate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25547: ('Invoke-MonitoringProbe Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25548: ('New-AddressBookPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25549: ('New-App Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25550: ('New-AuthServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25551: ('New-ClassificationRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25552: ('New-DlpPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25553: ('New-HybridConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25554: ('New-MailboxExportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25555: ('New-MailboxImportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25556: ('New-MailboxSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25557: ('New-MalwareFilterPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25558: ('New-MigrationBatch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25559: ('New-MigrationEndpoint Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25560: ('New-MobileDeviceMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25561: ('New-OnPremisesOrganization Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25562: ('New-PartnerApplication Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25563: ('New-PolicyTipConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25564: ('New-PowerShellVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25565: ('New-PublicFolderMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25566: ('New-ResourcePolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25567: ('New-SiteMailboxProvisioningPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25568: ('New-SyncMailPublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25569: ('New-UMCallAnsweringRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25570: ('New-WorkloadManagementPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25571: ('New-WorkloadPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25572: ('Redirect-Message Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25573: ('Remove-AddressBookPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25574: ('Remove-App Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25575: ('Remove-AuthServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25576: ('Remove-ClassificationRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25577: ('Remove-DlpPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25578: ('Remove-DlpPolicyTemplate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25579: ('Remove-GlobalMonitoringOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25580: ('Remove-HybridConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25581: ('Remove-LinkedUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25582: ('Remove-MailboxExportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25583: ('Remove-MailboxImportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25584: ('Remove-MailboxSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25585: ('Remove-MalwareFilterPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25586: ('Remove-MalwareFilterRecoveryItem Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25587: ('Remove-MigrationBatch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25588: ('Remove-MigrationEndpoint Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25589: ('Remove-MigrationUser Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25590: ('Remove-MobileDevice Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25591: ('Remove-MobileDeviceMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25592: ('Remove-OnPremisesOrganization Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25593: ('Remove-PartnerApplication Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25594: ('Remove-PolicyTipConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25595: ('Remove-PowerShellVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25596: ('Remove-PublicFolderMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25597: ('Remove-ResourcePolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25598: ('Remove-ResubmitRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25599: ('Remove-SiteMailboxProvisioningPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25600: ('Remove-UMCallAnsweringRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25601: ('Remove-UserPhoto Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25602: ('Remove-WorkloadManagementPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25603: ('Remove-WorkloadPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25604: ('Reset-ProvisioningCache Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25605: ('Resume-MailboxImportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25606: ('Resume-MalwareFilterRecoveryItem Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25607: ('Resume-PublicFolderMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25608: ('Set-ActiveSyncDeviceAccessRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25609: ('Set-AddressBookPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25610: ('Set-App Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25611: ('Set-AuthConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25612: ('Set-AuthServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25613: ('Set-ClassificationRuleCollection Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25614: ('Set-DlpPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25615: ('Set-FrontendTransportService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25616: ('Set-HybridConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25617: ('Set-HybridMailflow Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25618: ('Set-MailboxExportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25619: ('Set-MailboxImportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25620: ('Set-MailboxSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25621: ('Set-MailboxTransportService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25622: ('Set-MalwareFilteringServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25623: ('Set-MalwareFilterPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25624: ('Set-MigrationBatch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25625: ('Set-MigrationConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25626: ('Set-MigrationEndpoint Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25627: ('Set-MobileDeviceMailboxPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25628: ('Set-Notification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25629: ('Set-OnPremisesOrganization Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25630: ('Set-PartnerApplication Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25631: ('Set-PendingFederatedDomain Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25632: ('Set-PolicyTipConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25633: ('Set-PublicFolderMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25634: ('Set-ResourcePolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25635: ('Set-ResubmitRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25636: ('Set-RMSTemplate Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25637: ('Set-ServerComponentState Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25638: ('Set-ServerMonitor Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25639: ('Set-SiteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25640: ('Set-SiteMailboxProvisioningPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25641: ('Set-TransportService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25642: ('Set-UMCallAnsweringRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25643: ('Set-UMCallRouterSettings Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25644: ('Set-UMService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25645: ('Set-UserPhoto Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25646: ('Set-WorkloadPolicy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25647: ('Start-MailboxSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25648: ('Start-MigrationBatch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25649: ('Stop-MailboxSearch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25650: ('Stop-MigrationBatch Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25651: ('Suspend-MailboxExportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25652: ('Suspend-MailboxImportRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25653: ('Suspend-PublicFolderMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25654: ('Test-ArchiveConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25655: ('Test-MigrationServerAvailability Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25656: ('Test-OAuthConnectivity Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25657: ('Test-SiteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25658: ('Update-HybridConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25659: ('Update-PublicFolderMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25660: ('Update-SiteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25661: ('Add-AttachmentFilterEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25662: ('Remove-AttachmentFilterEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25663: ('New-AddressRewriteEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25664: ('Remove-AddressRewriteEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25665: ('Set-AddressRewriteEntry Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25666: ('Set-AttachmentFilterListConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25667: ('Set-MailboxSentItemsConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25668: ('Update-MovedMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25669: ('Disable-MalwareFilterRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25670: ('Enable-MalwareFilterRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25671: ('New-MalwareFilterRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25672: ('Remove-MalwareFilterRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25673: ('Set-MalwareFilterRule Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25674: ('Remove-MailboxRepairRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25675: ('Remove-ServerMonitoringOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25676: ('Update-ExchangeHelp Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25677: ('Update-StoreMailboxState Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25678: ('Disable-PushNotificationProxy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25679: ('Enable-PushNotificationProxy Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25680: ('New-PublicFolderMoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25681: ('Remove-PublicFolderMoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25682: ('Resume-PublicFolderMoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25683: ('Set-PublicFolderMoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25684: ('Suspend-PublicFolderMoveRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25685: ('Update-DatabaseSchema Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25686: ('Set-SearchDocumentFormat Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25687: ('New-AuthRedirect Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25688: ('New-CompliancePolicySyncNotification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25689: ('New-ComplianceServiceVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25690: ('New-DatabaseAvailabilityGroupConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25691: ('New-DataClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25692: ('New-Fingerprint Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25693: ('New-IntraOrganizationConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25694: ('New-MailboxDeliveryVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25695: ('New-MapiVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25696: ('New-OutlookServiceVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25697: ('New-RestVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25698: ('New-SearchDocumentFormat Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25699: ('New-SettingOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25700: ('New-SiteMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25701: ('Remove-AuthRedirect Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25702: ('Remove-CompliancePolicySyncNotification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25703: ('Remove-ComplianceServiceVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25704: ('Remove-DatabaseAvailabilityGroupConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25705: ('Remove-DataClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25706: ('Remove-IntraOrganizationConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25707: ('Remove-MailboxDeliveryVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25708: ('Remove-MapiVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25709: ('Remove-OutlookServiceVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25710: ('Remove-PublicFolderMailboxMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25711: ('Remove-PushNotificationSubscription Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25712: ('Remove-RestVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25713: ('Remove-SearchDocumentFormat Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25714: ('Remove-SettingOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25715: ('Remove-SyncMailPublicFolder Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25716: ('Resume-PublicFolderMailboxMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25717: ('Send-MapiSubmitSystemProbe Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25718: ('Set-AuthRedirect Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25719: ('Set-ClientAccessService Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25720: ('Set-Clutter Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25721: ('Set-ComplianceServiceVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25722: ('Set-ConsumerMailbox Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25723: ('Set-DatabaseAvailabilityGroupConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25724: ('Set-DataClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25725: ('Set-IntraOrganizationConnector Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25726: ('Set-LogExportVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25727: ('Set-MailboxDeliveryVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25728: ('Set-MapiVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25729: ('Set-OutlookServiceVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25730: ('Set-PublicFolderMailboxMigrationRequest Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25731: ('Set-RestVirtualDirectory Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25732: ('Set-SettingOverride Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25733: ('Set-SmimeConfig Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25734: ('Set-SubmissionMalwareFilteringServer Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25735: ('Set-UMMailboxConfiguration Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25736: ('Set-UnifiedAuditSetting Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25737: ('Start-AuditAssistant Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25738: ('Start-UMPhoneSession Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25739: ('Stop-UMPhoneSession Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25740: ('Test-DataClassification Exchange cmdlet issued', SOURCE_NONE),  # nopep8
    25741: ('Test-TextExtraction Exchange cmdlet issued', SOURCE_NONE),  # nopep8
}

EVENTS = {}
EVENTS.update(WINDOWS)
EVENTS.update(EXCHANGE)
EVENTS.update(SQL)
EVENTS.update(SECURITY)  # Use these descriptions over windows

if __name__ == '__main__':
    overlap = set(SECURITY) & set(WINDOWS)
    for evid in overlap:
        if SECURITY[evid] != WINDOWS[evid]:
            print(f'{evid}: {SECURITY[evid]} != {WINDOWS[evid]}')
