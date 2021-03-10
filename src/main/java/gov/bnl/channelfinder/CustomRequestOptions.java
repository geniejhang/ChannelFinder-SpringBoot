package gov.bnl.channelfinder;

import org.elasticsearch.client.HttpAsyncResponseConsumerFactory;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RequestOptions.Builder;
import org.springframework.beans.factory.annotation.Value;

public class CustomRequestOptions {
    @Value("${server.request.buffersize:104857600}")
    private int REQUEST_BUFFERSIZE;

    private RequestOptions largeBufferSizeRequestOption() {
        Builder builder = RequestOptions.DEFAULT.toBuilder();
        builder.setHttpAsyncResponseConsumerFactory(new HttpAsyncResponseConsumerFactory.HeapBufferedResponseConsumerFactory(REQUEST_BUFFERSIZE));
        return builder.build();
    }

    public static final RequestOptions LARGE_BUFFERSIZE_REQUEST_OPTION = new CustomRequestOptions().largeBufferSizeRequestOption();
}
