package codes.recursive;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fnproject.fn.testing.*;
import org.junit.*;

import java.io.IOException;
import java.util.Map;

import static org.junit.Assert.*;

public class KmsDemoFunctionTest {

    @Rule
    public final FnTestingRule testing = FnTestingRule.createDefault();

    @Test
    public void shouldDecryptPassword() throws IOException {
        testing.givenEvent().enqueue();
        testing.thenRun(KmsDemoFunction.class, "decryptSensitiveValue");

        FnResult result = testing.getOnlyResult();
        System.out.println(result.getBodyAsString());
        Map<String, String> resultMap = new ObjectMapper().readValue(result.getBodyAsString(), Map.class);
        assertEquals("hunter2", resultMap.get("decryptedPassword"));
    }

}