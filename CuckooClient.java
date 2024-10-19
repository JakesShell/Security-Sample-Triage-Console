package com.malware;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Properties;

public class CuckooClient {
    private String apiUrl;
    private String apiKey;

    public CuckooClient() {
        Properties properties = new Properties();
        try {
            properties.load(getClass().getClassLoader().getResourceAsStream("config.properties"));
            this.apiUrl = properties.getProperty("cuckoo.api.url");
            this.apiKey = properties.getProperty("cuckoo.api.key");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String submitSample(String filePath) throws IOException {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost(apiUrl + "/tasks/create/file");

        // Set headers
        post.setHeader("Authorization", "Bearer " + apiKey);
        post.setHeader("Content-Type", "application/json");

        // Set the body
        String json = "{\"file\": \"" + filePath + "\"}";
        post.setEntity(new StringEntity(json));

        // Execute the request
        CloseableHttpResponse response = client.execute(post);
        String result = EntityUtils.toString(response.getEntity());
        client.close();
        return result;
    }

    public String getTaskReport(int taskId) throws IOException {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost(apiUrl + "/tasks/view/" + taskId);

        post.setHeader("Authorization", "Bearer " + apiKey);
        post.setHeader("Content-Type", "application/json");

        CloseableHttpResponse response = client.execute(post);
        String result = EntityUtils.toString(response.getEntity());
        client.close();
        return result;
    }
}
