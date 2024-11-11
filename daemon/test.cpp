const string userName = "USER";
const string password = "password";
const string connectString = "";

Environment *env = Environment::createEnvironment();
{
   Connection *conn = env->createConnection(
      userName, password, connectString);
   Statement *stmt = conn->createStatement(
      "SELECT TRANSACTION-HISTORY FROM tran
       WHERE SELLER-ID = SID");
   ResultSet *rs = stmt->executeQuery();
   rs->next();
   Blob b = rs->getBlob(1);
   cout << "Length of BLOB : " << b.length();
   ...
   stmt->closeResultSet(rs);
   conn->terminateStatement(stmt);
   env->terminateConnection(conn);
}
Environment::terminateEnvironment(env);
