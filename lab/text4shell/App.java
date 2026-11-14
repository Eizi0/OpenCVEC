// Application de test volontairement vulnérable à CVE-2022-42889 (labo isolé uniquement).
// Elle interpole le paramètre « search » avec StringSubstitutor.createInterpolator(),
// comme le ferait un code applicatif imprudent.
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import org.apache.commons.text.StringSubstitutor;

public class App {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", exchange -> {
            String q = exchange.getRequestURI().getRawQuery();
            String out = "ok";
            if (q != null) {
                for (String kv : q.split("&")) {
                    String[] p = kv.split("=", 2);
                    if (p.length == 2 && p[0].equals("search")) {
                        String v = URLDecoder.decode(p[1], StandardCharsets.UTF_8);
                        try {
                            out = StringSubstitutor.createInterpolator().replace(v);
                        } catch (Exception e) {
                            out = "erreur";
                        }
                    }
                }
            }
            byte[] b = ("recherche : " + out + "\n").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, b.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(b); }
        });
        server.start();
        System.out.println("text4shell-lab en écoute sur 8080");
    }
}
