# Concept List for Mountainash Auth Client

Total concepts: 85

## Foundation Concepts (1-10)

1. OAuth 2.0 Basics
2. OAuth 1.0a Basics
3. Bearer Tokens
4. API Keys
5. Pydantic Models
6. Frozen Models
7. Python Protocols
8. Context Managers
9. File Permissions
10. Atomic File Writes

## Auth Type System (11-26)

11. AuthSpec Base Model
12. Discriminated Union
13. Literal Kind Discriminator
14. NoAuth Type
15. PasswordAuth Type
16. TokenAuth Type
17. JWTAuth Type
18. OAuth2Auth Type
19. OAuth2AuthCodeAuth Type
20. OAuth1Auth Type
21. IAMAuth Type
22. AzureADAuth Type
23. WindowsAuth Type
24. KerberosAuth Type
25. CertificateAuth Type
26. ServiceAccountAuth Type

## Auth Dispatch (27-32)

27. Auth Dispatch Registry
28. Auth To Driver Kwargs
29. Auth Kwargs Function
30. Type Based Dispatch
31. Unmapped Auth Types
32. Backend Specific Handling

## OAuth 2.0 Flow (33-44)

33. OAuthFlow Class
34. Authorization Code Grant
35. PKCE Extension
36. Code Verifier
37. Code Challenge
38. Build Authorize URL
39. State Parameter
40. Exchange Code
41. Token Exchange
42. Refresh Token
43. Token Expiry Check
44. End To End Authorize

## OAuth 1.0a Flow (45-50)

45. OAuth1Flow Class
46. Request Token
47. Three Legged Flow
48. Verifier Exchange
49. Authlib Dependency
50. Optional Import Guard

## Connection Mixins (51-63)

51. OAuth2ConnectionMixin
52. Connect Method
53. Auto Authorize Flag
54. Client Property
55. Context Manager Support
56. Profile Parameter
57. Token Lifecycle Overview
58. No Token State
59. Valid Token State
60. Expired With Refresh State
61. Expired No Refresh State
62. Cleared State
63. File Locked Refresh

## Secret Storage (64-74)

64. SecretStore Protocol
65. Load Method
66. Save Method
67. Clear Method
68. Is Cleared Method
69. List Users Method
70. Lock Method
71. FilesystemStore
72. YAML Serialization
73. Domain Provider Namespace
74. Tombstone Semantics

## Callback Server (75-79)

75. LocalCallbackServer
76. Ephemeral HTTP Server
77. Callback Capture
78. Prompt For Code
79. Manual Redirect Mode

## Error Handling (80-85)

80. TokenExchangeError
81. Token Exchange URL
82. TokenRefreshError
83. Refresh Status Code
84. AuthorizationRequired
85. Provider User Context
