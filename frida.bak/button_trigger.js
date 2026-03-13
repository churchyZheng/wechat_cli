Interceptor.attach(
    ObjC.classes.NSEvent["- keyCode"].implementation,
    {
        onLeave(retval) {
            try {
                // 36 = Return(Enter)
                if (retval.toInt32() === 36) {
                    console.log("\n===== ENTER PRESSED (System Level) =====");

                    // 打印调用栈
                    console.log(
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress)
                            .join("\n")
                    );
                    console.log("========================================\n");
                }
            } catch (e) {}
        }
    }
);
