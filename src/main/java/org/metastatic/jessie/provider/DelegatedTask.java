/* DelegatedTask.java --
   Copyright (C) 2006  Free Software Foundation, Inc.

This file is a part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version. */


package org.metastatic.jessie.provider;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Casey Marshall (csm@gnu.org)
 */
public abstract class DelegatedTask implements Runnable
{
    private static final Logger logger = Logger.getLogger(DelegatedTask.class.getName());
    private final AtomicBoolean hasRun;
    protected Throwable thrown;

    protected DelegatedTask()
    {
        hasRun = new AtomicBoolean(false);
    }

    public final void run()
    {
        if (!hasRun.compareAndSet(false, true))
            throw new IllegalStateException("task already ran");
        try
        {
            if (Debug.DEBUG)
                logger.log(Level.FINE,
                           "running delegated task {0} in {1}",
                           new Object[] { this, Thread.currentThread() });
            implRun();
        }
        catch (Throwable t)
        {
            if (Debug.DEBUG)
                logger.log(Level.FINE, "task threw exception", t);
            thrown = t;
        }
    }

    public final boolean hasRun()
    {
        return hasRun.get();
    }

    public final Throwable thrown()
    {
        return thrown;
    }

    protected abstract void implRun() throws Throwable;
}
