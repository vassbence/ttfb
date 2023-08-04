package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func HandleRequest(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if event.Headers["x-latency-secret"] != os.Getenv("LATENCY_CLOUDFRONT_SECRET") {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 403,
		}, nil
	}

	if event.QueryStringParameters["url"] == "" {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
		}, nil
	}

	var start, ttfb time.Time
	var redirects = 0

	req, _ := http.NewRequest("GET", event.QueryStringParameters["url"], nil)

	trace := &httptrace.ClientTrace{
		GotConn:              func(_ httptrace.GotConnInfo) { redirects += 1 },
		GotFirstResponseByte: func() { ttfb = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("max redirects exceeded")
			}

			return nil
		},
	}

	start = time.Now()
	response, err := client.Do(req)

	if err != nil {
		var responseJson, _ = json.Marshal(map[string]interface{}{
			"url":    event.QueryStringParameters["url"],
			"status": "request_failed",
		})

		return events.APIGatewayV2HTTPResponse{
			StatusCode: 200,
			Body:       string(responseJson),
			Headers: map[string]string{
				"x-latency-region": os.Getenv("LATENCY_AWS_REGION"),
			},
		}, nil
	}
	defer response.Body.Close()

	var responseJson, _ = json.Marshal(map[string]interface{}{
		"start_url": event.QueryStringParameters["url"],
		"final_url": response.Request.URL.String(),
		"status":    response.StatusCode,
		"ttfb":      int(ttfb.Sub(start).Milliseconds()),
		"redirects": redirects - 1,
	})

	return events.APIGatewayV2HTTPResponse{
		StatusCode: 200,
		Body:       string(responseJson),
		Headers: map[string]string{
			"x-latency-region": os.Getenv("LATENCY_AWS_REGION"),
		},
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
