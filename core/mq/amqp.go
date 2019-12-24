package mq

import (
	"bytes"
	"encoding/gob"
	"github.com/nim4/cyrus/core/models"
	"github.com/streadway/amqp"
	"log"
)

var conn *amqp.Connection
var ch *amqp.Channel

func Connect(declareExchange bool) error {
	var err error
	conn, err = amqp.Dial(models.Config.RabbitMQ.Addr)
	if err != nil {
		return err
	}

	ch, err = conn.Channel()
	if err != nil {
		return err
	}

	if declareExchange {
		return ch.ExchangeDeclare(
			models.Config.RabbitMQ.ExchangeName,
			amqp.ExchangeFanout,
			false,
			false,
			false,
			false,
			nil,
		)
	}
	return nil
}

func Publish(rec models.Record) error {
	b := new(bytes.Buffer)
	err := gob.NewEncoder(b).Encode(rec)
	if err != nil {
		return err
	}
	return ch.Publish(
		models.Config.RabbitMQ.ExchangeName,
		"",
		false,
		false,
		amqp.Publishing{
			ContentType: "application/octet-stream",
			Body:        b.Bytes(),
		})
}

func Subscribe(queueName string) (chan models.Record, error) {
	q, err := ch.QueueDeclare(
		queueName,
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return nil, err
	}

	err = ch.QueueBind(
		q.Name,                              // queue name
		"",                                  // routing key
		models.Config.RabbitMQ.ExchangeName, // exchange
		false,
		nil)
	if err != nil {
		return nil, err
	}

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		return nil, err
	}

	recChannel := make(chan models.Record, 256)

	go func() {
		for d := range msgs {
			rec := models.Record{}
			b := bytes.NewReader(d.Body)
			err = gob.NewDecoder(b).Decode(&rec)
			if err != nil {
				log.Print("Decoding message failed, Droping message.")
				d.Reject(false)
				continue
			}
			recChannel <- rec
			d.Ack(false)
		}
	}()
	return recChannel, nil
}
