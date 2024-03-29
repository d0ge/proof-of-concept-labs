/*
 * This file is generated by jOOQ.
 */
package one.d4d.jooq.model;


import one.d4d.jooq.model.tables.Example;
import one.d4d.jooq.model.tables.records.ExampleRecord;

import org.jooq.TableField;
import org.jooq.UniqueKey;
import org.jooq.impl.DSL;
import org.jooq.impl.Internal;


/**
 * A class modelling foreign key relationships and constraints of tables in
 * public.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes" })
public class Keys {

    // -------------------------------------------------------------------------
    // UNIQUE and PRIMARY KEY definitions
    // -------------------------------------------------------------------------

    public static final UniqueKey<ExampleRecord> EXAMPLE_PKEY = Internal.createUniqueKey(Example.EXAMPLE, DSL.name("example_pkey"), new TableField[] { Example.EXAMPLE.ID }, true);
}
