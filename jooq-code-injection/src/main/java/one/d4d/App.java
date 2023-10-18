package one.d4d;

import one.d4d.jooq.model.tables.Example;
import one.d4d.jooq.model.tables.records.ExampleRecord;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.Record;
import org.jooq.Result;
import org.jooq.SQLDialect;
import org.jooq.codegen.GenerationTool;
import org.jooq.impl.DSL;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
        System.out.println("[***] Proof of concept");
        try {
            String url = "jdbc:postgresql://127.0.0.1:5432/code";
            Connection conn = DriverManager.getConnection(url, "doge", "");
            DSLContext context = DSL.using(conn, SQLDialect.POSTGRES);
            String vulnerability = "ID";
            Field id = DSL.field(vulnerability);
            Result<Record> authors = context.select()
                    .from(Example.EXAMPLE)
                    .where(id.eq("1"))
                    .fetch();
            System.out.println(authors.stream().findFirst());
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
